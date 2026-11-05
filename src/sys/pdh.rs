//! Hardware counters through PDH (the same source as Task Manager): CPU, disk, GPU engines
//! and GPU memory. Memory comes from `GlobalMemoryStatusEx`.

use super::{from_wide, wide};
use windows::Win32::System::Performance::{
    PDH_FMT_COUNTERVALUE, PDH_FMT_DOUBLE, PDH_HCOUNTER, PDH_HQUERY, PDH_MORE_DATA, PdhAddEnglishCounterW, PdhCloseQuery, PdhCollectQueryData, PdhExpandWildCardPathW, PdhGetFormattedCounterValue,
    PdhOpenQueryW,
};
use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
use windows::core::{PCWSTR, PWSTR};

#[derive(Clone, Debug, Default)]
pub struct Sample {
    pub cpu_pct: f32,
    pub memory_used: f64,
    pub memory_total: f64,
    pub disk_read: f64,
    pub disk_write: f64,
    /// `None` when the machine has no GPU engine counters.
    pub gpu_pct: Option<f32>,
    pub gpu_memory: Option<f64>,
    /// Per program (instances of one exe summed): name, CPU % of the whole machine, private
    /// working set in bytes, I/O bytes/sec. No GPU split.
    pub apps: Vec<(String, f32, f64, f64)>,
}

type Handle = PDH_HCOUNTER;

struct Query {
    handle: PDH_HQUERY,
}

impl Query {
    fn open() -> Result<Self, String> {
        let mut handle = PDH_HQUERY::default();
        let rc = unsafe { PdhOpenQueryW(PCWSTR::null(), 0, &mut handle) };
        if rc != 0 {
            return Err(format!("PdhOpenQuery failed (0x{rc:08x})"));
        }
        Ok(Self { handle })
    }

    fn add(&self, path: &str) -> Option<Handle> {
        let p = wide(path);
        let mut counter = PDH_HCOUNTER::default();
        let rc = unsafe { PdhAddEnglishCounterW(self.handle, PCWSTR(p.as_ptr()), 0, &mut counter) };
        (rc == 0).then_some(counter)
    }

    fn collect(&self) -> bool {
        unsafe { PdhCollectQueryData(self.handle) == 0 }
    }
}

impl Drop for Query {
    fn drop(&mut self) {
        unsafe {
            PdhCloseQuery(self.handle);
        }
    }
}

fn value(counter: Handle) -> Option<f64> {
    let mut v = PDH_FMT_COUNTERVALUE::default();
    let rc = unsafe { PdhGetFormattedCounterValue(counter, PDH_FMT_DOUBLE, None, &mut v) };
    // CStatus 0 is VALID_DATA and 1 is NEW_DATA; both are usable.
    (rc == 0 && v.CStatus <= 1).then_some(unsafe { v.Anonymous.doubleValue })
}

/// Expands a wildcard counter path (`\GPU Engine(*)\Utilization Percentage`) into concrete paths.
fn expand(pattern: &str) -> Vec<String> {
    let pat = wide(pattern);
    let mut len = 0u32;
    let rc = unsafe { PdhExpandWildCardPathW(PCWSTR::null(), PCWSTR(pat.as_ptr()), None, &mut len, 0) };
    if rc != PDH_MORE_DATA || len == 0 {
        return Vec::new();
    }
    let mut buf = vec![0u16; len as usize];
    let rc = unsafe { PdhExpandWildCardPathW(PCWSTR::null(), PCWSTR(pat.as_ptr()), Some(PWSTR(buf.as_mut_ptr())), &mut len, 0) };
    if rc != 0 {
        return Vec::new();
    }
    buf.split(|c| *c == 0).filter(|s| !s.is_empty()).map(from_wide).collect()
}

/// Engine type from a `GPU Engine` instance path (`..._engtype_3D)\Utilization...`).
pub fn engine_type(path: &str) -> &str {
    let start = path.find("engtype_").map_or(0, |i| i + "engtype_".len());
    let rest = &path[start..];
    rest.split(')').next().unwrap_or(rest)
}

/// Task Manager style GPU load: the busiest engine type, each summed over all processes.
pub fn gpu_load(values: &[(String, f64)]) -> f32 {
    let mut per_type: Vec<(&str, f64)> = Vec::new();
    for (path, v) in values {
        let t = engine_type(path);
        match per_type.iter_mut().find(|(n, _)| *n == t) {
            Some((_, sum)) => *sum += v,
            None => per_type.push((t, *v)),
        }
    }
    per_type.iter().map(|(_, s)| *s).fold(0.0, f64::max).min(100.0) as f32
}

/// Per-process counters; instance names are the exe name, with `#n` for duplicates.
struct ProcQuery {
    query: Query,
    procs: Vec<(String, Handle, Handle, Handle)>,
}

impl ProcQuery {
    fn build() -> Option<Self> {
        let query = Query::open().ok()?;
        let procs: Vec<_> = expand(r"\Process(*)\% Processor Time")
            .into_iter()
            .filter_map(|p| {
                let name = p.split_once('(')?.1.rsplit_once(")\\")?.0.to_owned();
                if name == "_Total" || name == "Idle" {
                    return None;
                }
                let cpu = query.add(&p)?;
                let mem = query.add(&format!(r"\Process({name})\Working Set - Private"))?;
                let io = query.add(&format!(r"\Process({name})\IO Data Bytes/sec"))?;
                Some((name.rsplit_once('#').map_or(name.as_str(), |(n, _)| n).to_owned(), cpu, mem, io))
            })
            .collect();
        query.collect();
        (!procs.is_empty()).then_some(Self { query, procs })
    }
}

pub struct Pdh {
    procs: Option<ProcQuery>,
    cores: f32,
    main: Query,
    cpu: Option<Handle>,
    disk_read: Option<Handle>,
    disk_write: Option<Handle>,
    gpu: Option<GpuQuery>,
    gpu_refreshed: std::time::Instant,
}

struct GpuQuery {
    query: Query,
    engines: Vec<(String, Handle)>,
    memory: Vec<Handle>,
}

impl GpuQuery {
    fn build() -> Option<Self> {
        let query = Query::open().ok()?;
        let engines: Vec<(String, Handle)> = expand(r"\GPU Engine(*)\Utilization Percentage").into_iter().filter_map(|p| query.add(&p).map(|h| (p, h))).collect();
        let memory: Vec<Handle> = expand(r"\GPU Adapter Memory(*)\Dedicated Usage").into_iter().filter_map(|p| query.add(&p)).collect();
        if engines.is_empty() && memory.is_empty() {
            return None;
        }
        query.collect();
        Some(Self { query, engines, memory })
    }
}

impl Pdh {
    pub fn new() -> Result<Self, String> {
        let main = Query::open()?;
        // Task Manager's Utilisation follows "% Processor Time"; "% Processor Utility" counts turbo
        // boost and reads about 1.5x higher.
        let cpu = main.add(r"\Processor Information(_Total)\% Processor Time").or_else(|| main.add(r"\Processor(_Total)\% Processor Time"));
        let disk_read = main.add(r"\PhysicalDisk(_Total)\Disk Read Bytes/sec");
        let disk_write = main.add(r"\PhysicalDisk(_Total)\Disk Write Bytes/sec");
        if cpu.is_none() && disk_read.is_none() {
            return Err("No performance counters could be opened".into());
        }
        main.collect();
        let cores = std::thread::available_parallelism().map_or(1, |n| n.get()) as f32;
        Ok(Self { procs: ProcQuery::build(), cores, main, cpu, disk_read, disk_write, gpu: GpuQuery::build(), gpu_refreshed: std::time::Instant::now() })
    }

    /// One sample; call about once per second (rate counters need the previous collection).
    pub fn sample(&mut self) -> Sample {
        // Processes come and go, and so do their GPU instances.
        let rebuilt = self.gpu_refreshed.elapsed().as_secs() >= 15;
        if rebuilt {
            self.gpu = GpuQuery::build();
            self.procs = ProcQuery::build();
            self.gpu_refreshed = std::time::Instant::now();
        }
        self.main.collect();
        let mut s = Sample {
            cpu_pct: self.cpu.and_then(value).unwrap_or(0.0).clamp(0.0, 100.0) as f32,
            disk_read: self.disk_read.and_then(value).unwrap_or(0.0),
            disk_write: self.disk_write.and_then(value).unwrap_or(0.0),
            ..Sample::default()
        };
        let mut mem = MEMORYSTATUSEX { dwLength: size_of::<MEMORYSTATUSEX>() as u32, ..Default::default() };
        if unsafe { GlobalMemoryStatusEx(&mut mem) }.is_ok() {
            s.memory_total = mem.ullTotalPhys as f64;
            s.memory_used = (mem.ullTotalPhys - mem.ullAvailPhys) as f64;
        }
        // A query built this second has no earlier reading to take a rate against, so it sits this sample out.
        if let Some(p) = self.procs.as_ref().filter(|_| !rebuilt)
            && p.query.collect()
        {
            for (name, cpu, mem, io) in &p.procs {
                let (c, m, i) = (value(*cpu).unwrap_or(0.0) as f32 / self.cores, value(*mem).unwrap_or(0.0), value(*io).unwrap_or(0.0));
                match s.apps.iter_mut().find(|a| a.0 == *name) {
                    Some(a) => (a.1, a.2, a.3) = (a.1 + c, a.2 + m, a.3 + i),
                    None => s.apps.push((name.clone(), c, m, i)),
                }
            }
        }
        if let Some(g) = self.gpu.as_ref().filter(|_| !rebuilt)
            && g.query.collect()
        {
            let loads: Vec<(String, f64)> = g.engines.iter().filter_map(|(p, h)| value(*h).map(|v| (p.clone(), v))).collect();
            if !g.engines.is_empty() {
                s.gpu_pct = Some(gpu_load(&loads));
            }
            if !g.memory.is_empty() {
                s.gpu_memory = Some(g.memory.iter().filter_map(|h| value(*h)).sum());
            }
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_types_are_parsed() {
        let p = r"\GPU Engine(pid_12_luid_0x0_0x1_phys_0_eng_0_engtype_3D)\Utilization Percentage";
        assert_eq!(engine_type(p), "3D");
        assert_eq!(engine_type(r"\GPU Engine(pid_1_engtype_VideoDecode)\Utilization Percentage"), "VideoDecode");
    }

    #[test]
    fn gpu_load_is_busiest_engine_type() {
        let v = vec![(r"\GPU Engine(pid_1_engtype_3D)\U".to_string(), 30.0), (r"\GPU Engine(pid_2_engtype_3D)\U".to_string(), 25.0), (r"\GPU Engine(pid_2_engtype_Copy)\U".to_string(), 80.0)];
        assert_eq!(gpu_load(&v), 80.0);
        assert_eq!(gpu_load(&[]), 0.0);
    }
}
