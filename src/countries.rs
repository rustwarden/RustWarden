//! ISO country table: alpha-2 code (what GeoIP databases give us), alpha-3 code
//! (what `assets/world.bin` uses), English name and a rough centroid for the map
//! when the database has no coordinates (GeoLite2-Country has none).

pub struct Entry {
    pub a2: &'static str,
    pub a3: &'static str,
    pub name: &'static str,
    pub lon: f32,
    pub lat: f32,
}

macro_rules! table {
    ($(($a2:literal, $a3:literal, $name:literal, $lon:literal, $lat:literal)),* $(,)?) => {
        pub const TABLE: &[Entry] = &[$(Entry { a2: $a2, a3: $a3, name: $name, lon: $lon, lat: $lat }),*];
    };
}

table! {
    ("AD", "AND", "Andorra", 1.6, 42.5),
    ("AE", "ARE", "United Arab Emirates", 54.0, 24.0),
    ("AF", "AFG", "Afghanistan", 66.0, 33.9),
    ("AG", "ATG", "Antigua and Barbuda", -61.8, 17.1),
    ("AL", "ALB", "Albania", 20.0, 41.0),
    ("AM", "ARM", "Armenia", 45.0, 40.2),
    ("AO", "AGO", "Angola", 17.9, -12.3),
    ("AZ", "AZE", "Azerbaijan", 47.6, 40.3),
    ("BA", "BIH", "Bosnia and Herzegovina", 17.8, 44.2),
    ("BB", "BRB", "Barbados", -59.5, 13.2),
    ("BD", "BGD", "Bangladesh", 90.3, 23.7),
    ("BF", "BFA", "Burkina Faso", -1.6, 12.3),
    ("BH", "BHR", "Bahrain", 50.6, 26.0),
    ("BI", "BDI", "Burundi", 29.9, -3.4),
    ("BJ", "BEN", "Benin", 2.3, 9.3),
    ("BN", "BRN", "Brunei", 114.7, 4.5),
    ("BO", "BOL", "Bolivia", -64.7, -16.3),
    ("BS", "BHS", "Bahamas", -77.4, 25.0),
    ("BT", "BTN", "Bhutan", 90.4, 27.5),
    ("BW", "BWA", "Botswana", 24.7, -22.3),
    ("BZ", "BLZ", "Belize", -88.5, 17.2),
    ("CD", "COD", "DR Congo", 23.7, -2.9),
    ("CF", "CAF", "Central African Republic", 20.9, 6.6),
    ("CG", "COG", "Congo", 15.8, -0.2),
    ("CI", "CIV", "Ivory Coast", -5.5, 7.5),
    ("CM", "CMR", "Cameroon", 12.4, 5.7),
    ("CR", "CRI", "Costa Rica", -84.0, 9.7),
    ("CU", "CUB", "Cuba", -77.8, 21.5),
    ("CV", "CPV", "Cape Verde", -23.6, 15.1),
    ("CY", "CYP", "Cyprus", 33.4, 35.1),
    ("DJ", "DJI", "Djibouti", 42.6, 11.8),
    ("DM", "DMA", "Dominica", -61.4, 15.4),
    ("DO", "DOM", "Dominican Republic", -70.2, 18.7),
    ("DZ", "DZA", "Algeria", 2.6, 28.0),
    ("EC", "ECU", "Ecuador", -78.1, -1.8),
    ("ER", "ERI", "Eritrea", 39.8, 15.2),
    ("ET", "ETH", "Ethiopia", 40.5, 9.1),
    ("FJ", "FJI", "Fiji", 178.1, -17.7),
    ("GA", "GAB", "Gabon", 11.6, -0.8),
    ("GD", "GRD", "Grenada", -61.7, 12.1),
    ("GE", "GEO", "Georgia", 43.4, 42.3),
    ("GH", "GHA", "Ghana", -1.0, 7.9),
    ("GM", "GMB", "Gambia", -15.3, 13.4),
    ("GN", "GIN", "Guinea", -10.9, 10.4),
    ("GQ", "GNQ", "Equatorial Guinea", 10.3, 1.7),
    ("GT", "GTM", "Guatemala", -90.2, 15.7),
    ("GW", "GNB", "Guinea-Bissau", -15.2, 12.0),
    ("GY", "GUY", "Guyana", -58.9, 4.9),
    ("HN", "HND", "Honduras", -86.6, 14.8),
    ("HT", "HTI", "Haiti", -72.7, 19.0),
    ("IQ", "IRQ", "Iraq", 43.7, 33.2),
    ("JM", "JAM", "Jamaica", -77.3, 18.1),
    ("JO", "JOR", "Jordan", 36.8, 31.2),
    ("KG", "KGZ", "Kyrgyzstan", 74.6, 41.5),
    ("KH", "KHM", "Cambodia", 104.9, 12.6),
    ("KI", "KIR", "Kiribati", 173.0, 1.9),
    ("KM", "COM", "Comoros", 43.9, -11.9),
    ("KN", "KNA", "Saint Kitts and Nevis", -62.7, 17.3),
    ("KP", "PRK", "North Korea", 127.2, 40.3),
    ("KW", "KWT", "Kuwait", 47.6, 29.3),
    ("LA", "LAO", "Laos", 102.5, 19.9),
    ("LB", "LBN", "Lebanon", 35.9, 33.9),
    ("LC", "LCA", "Saint Lucia", -61.0, 13.9),
    ("LI", "LIE", "Liechtenstein", 9.6, 47.2),
    ("LK", "LKA", "Sri Lanka", 80.8, 7.9),
    ("LR", "LBR", "Liberia", -9.4, 6.4),
    ("LS", "LSO", "Lesotho", 28.2, -29.6),
    ("LY", "LBY", "Libya", 17.2, 27.0),
    ("MC", "MCO", "Monaco", 7.4, 43.7),
    ("ME", "MNE", "Montenegro", 19.3, 42.7),
    ("MG", "MDG", "Madagascar", 46.9, -19.4),
    ("MK", "MKD", "North Macedonia", 21.7, 41.6),
    ("ML", "MLI", "Mali", -3.5, 17.6),
    ("MM", "MMR", "Myanmar", 96.0, 21.9),
    ("MN", "MNG", "Mongolia", 103.8, 46.9),
    ("MO", "MAC", "Macao", 113.5, 22.2),
    ("MR", "MRT", "Mauritania", -10.9, 20.3),
    ("MT", "MLT", "Malta", 14.4, 35.9),
    ("MU", "MUS", "Mauritius", 57.6, -20.3),
    ("MV", "MDV", "Maldives", 73.2, 3.2),
    ("MW", "MWI", "Malawi", 34.3, -13.3),
    ("MZ", "MOZ", "Mozambique", 35.5, -18.7),
    ("NA", "NAM", "Namibia", 17.1, -22.6),
    ("NE", "NER", "Niger", 8.1, 17.6),
    ("NI", "NIC", "Nicaragua", -85.2, 12.9),
    ("NP", "NPL", "Nepal", 84.1, 28.4),
    ("NR", "NRU", "Nauru", 166.9, -0.5),
    ("OM", "OMN", "Oman", 55.9, 21.5),
    ("PA", "PAN", "Panama", -80.8, 8.5),
    ("PG", "PNG", "Papua New Guinea", 143.9, -6.3),
    ("PS", "PSE", "Palestine", 35.2, 31.9),
    ("PW", "PLW", "Palau", 134.6, 7.5),
    ("PY", "PRY", "Paraguay", -58.4, -23.4),
    ("QA", "QAT", "Qatar", 51.2, 25.3),
    ("RW", "RWA", "Rwanda", 29.9, -1.9),
    ("SB", "SLB", "Solomon Islands", 160.2, -9.6),
    ("SC", "SYC", "Seychelles", 55.5, -4.7),
    ("SD", "SDN", "Sudan", 30.2, 12.9),
    ("SL", "SLE", "Sierra Leone", -11.8, 8.5),
    ("SM", "SMR", "San Marino", 12.5, 43.9),
    ("SN", "SEN", "Senegal", -14.5, 14.5),
    ("SO", "SOM", "Somalia", 46.2, 5.2),
    ("SR", "SUR", "Suriname", -56.0, 3.9),
    ("SS", "SSD", "South Sudan", 31.3, 7.9),
    ("ST", "STP", "Sao Tome and Principe", 6.6, 0.2),
    ("SV", "SLV", "El Salvador", -88.9, 13.8),
    ("SY", "SYR", "Syria", 38.9, 35.0),
    ("SZ", "SWZ", "Eswatini", 31.5, -26.5),
    ("TD", "TCD", "Chad", 18.7, 15.5),
    ("TG", "TGO", "Togo", 0.8, 8.6),
    ("TJ", "TJK", "Tajikistan", 71.3, 38.9),
    ("TL", "TLS", "Timor-Leste", 125.7, -8.9),
    ("TM", "TKM", "Turkmenistan", 59.6, 39.0),
    ("TN", "TUN", "Tunisia", 9.5, 34.0),
    ("TO", "TON", "Tonga", -175.2, -21.2),
    ("TT", "TTO", "Trinidad and Tobago", -61.2, 10.7),
    ("TV", "TUV", "Tuvalu", 177.6, -7.5),
    ("TZ", "TZA", "Tanzania", 34.9, -6.4),
    ("UG", "UGA", "Uganda", 32.3, 1.4),
    ("UY", "URY", "Uruguay", -55.8, -32.5),
    ("UZ", "UZB", "Uzbekistan", 64.6, 41.4),
    ("VA", "VAT", "Vatican City", 12.5, 41.9),
    ("VC", "VCT", "Saint Vincent and the Grenadines", -61.2, 13.3),
    ("VE", "VEN", "Venezuela", -66.6, 6.4),
    ("VU", "VUT", "Vanuatu", 166.9, -15.4),
    ("WS", "WSM", "Samoa", -172.1, -13.8),
    ("XK", "XKX", "Kosovo", 20.9, 42.6),
    ("YE", "YEM", "Yemen", 48.5, 15.6),
    ("ZM", "ZMB", "Zambia", 27.8, -13.1),
    ("ZW", "ZWE", "Zimbabwe", 29.2, -19.0),
    ("AR", "ARG", "Argentina", -64.0, -34.0), ("AT", "AUT", "Austria", 14.5, 47.5),
    ("AU", "AUS", "Australia", 134.0, -25.0), ("BE", "BEL", "Belgium", 4.5, 50.6),
    ("BG", "BGR", "Bulgaria", 25.5, 42.7), ("BR", "BRA", "Brazil", -52.0, -10.0),
    ("BY", "BLR", "Belarus", 28.0, 53.7), ("CA", "CAN", "Canada", -96.0, 57.0),
    ("CH", "CHE", "Switzerland", 8.2, 46.8), ("CL", "CHL", "Chile", -71.0, -33.0),
    ("CN", "CHN", "China", 104.0, 35.0), ("CO", "COL", "Colombia", -74.0, 4.6),
    ("CZ", "CZE", "Czechia", 15.5, 49.8), ("DE", "DEU", "Germany", 10.4, 51.1),
    ("DK", "DNK", "Denmark", 9.5, 56.0), ("EE", "EST", "Estonia", 25.0, 58.6),
    ("EG", "EGY", "Egypt", 30.0, 26.0), ("ES", "ESP", "Spain", -3.7, 40.2),
    ("FI", "FIN", "Finland", 26.0, 64.0), ("FR", "FRA", "France", 2.2, 46.6),
    ("GB", "GBR", "United Kingdom", -2.0, 54.0), ("GR", "GRC", "Greece", 22.0, 39.0),
    ("HK", "HKG", "Hong Kong", 114.2, 22.3), ("HR", "HRV", "Croatia", 16.0, 45.1),
    ("HU", "HUN", "Hungary", 19.5, 47.2), ("ID", "IDN", "Indonesia", 113.9, -0.8),
    ("IE", "IRL", "Ireland", -8.0, 53.2), ("IL", "ISR", "Israel", 35.0, 31.4),
    ("IN", "IND", "India", 79.0, 22.0), ("IR", "IRN", "Iran", 53.7, 32.4),
    ("IS", "ISL", "Iceland", -19.0, 65.0), ("IT", "ITA", "Italy", 12.5, 42.8),
    ("JP", "JPN", "Japan", 138.0, 37.0), ("KE", "KEN", "Kenya", 37.9, 0.2),
    ("KR", "KOR", "South Korea", 127.8, 36.5), ("KZ", "KAZ", "Kazakhstan", 67.0, 48.0),
    ("LT", "LTU", "Lithuania", 23.9, 55.3), ("LU", "LUX", "Luxembourg", 6.1, 49.8),
    ("LV", "LVA", "Latvia", 24.9, 56.9), ("MA", "MAR", "Morocco", -6.0, 31.8),
    ("MD", "MDA", "Moldova", 28.4, 47.2), ("MX", "MEX", "Mexico", -102.0, 23.6),
    ("MY", "MYS", "Malaysia", 102.0, 4.2), ("NG", "NGA", "Nigeria", 8.7, 9.6),
    ("NL", "NLD", "Netherlands", 5.3, 52.2), ("NO", "NOR", "Norway", 9.0, 61.0),
    ("NZ", "NZL", "New Zealand", 172.0, -41.0), ("PE", "PER", "Peru", -75.0, -9.2),
    ("PH", "PHL", "Philippines", 122.0, 12.9), ("PK", "PAK", "Pakistan", 69.3, 30.4),
    ("PL", "POL", "Poland", 19.1, 52.1), ("PT", "PRT", "Portugal", -8.0, 39.6),
    ("RO", "ROU", "Romania", 25.0, 45.9), ("RS", "SRB", "Serbia", 20.8, 44.0),
    ("RU", "RUS", "Russia", 100.0, 60.0), ("SA", "SAU", "Saudi Arabia", 45.0, 24.0),
    ("SE", "SWE", "Sweden", 15.0, 62.0), ("SG", "SGP", "Singapore", 103.8, 1.35),
    ("SI", "SVN", "Slovenia", 14.8, 46.1), ("SK", "SVK", "Slovakia", 19.5, 48.7),
    ("TH", "THA", "Thailand", 101.0, 15.0), ("TR", "TUR", "Turkey", 35.0, 39.0),
    ("TW", "TWN", "Taiwan", 121.0, 23.7), ("UA", "UKR", "Ukraine", 31.2, 48.8),
    ("US", "USA", "United States", -98.0, 38.0), ("VN", "VNM", "Vietnam", 106.0, 16.0),
    ("ZA", "ZAF", "South Africa", 25.0, -29.0),
}

pub fn by_a2(code: [u8; 2]) -> Option<&'static Entry> {
    let code = [code[0].to_ascii_uppercase(), code[1].to_ascii_uppercase()];
    TABLE.iter().find(|e| e.a2.as_bytes() == code)
}

pub fn parse_a2(code: &str) -> Option<[u8; 2]> {
    let b = code.as_bytes();
    (b.len() == 2 && b.iter().all(u8::is_ascii_alphabetic)).then(|| [b[0].to_ascii_uppercase(), b[1].to_ascii_uppercase()])
}

/// Entries whose name contains `q` or whose code starts with it, best (prefix) matches first.
pub fn search(q: &str) -> Vec<&'static Entry> {
    let q = q.trim().to_lowercase();
    let mut hits: Vec<_> = TABLE.iter().filter(|e| e.name.to_lowercase().contains(&q) || e.a2.to_lowercase().starts_with(&q)).collect();
    hits.sort_by_key(|e| !(e.a2.eq_ignore_ascii_case(&q) || e.name.to_lowercase().starts_with(&q)));
    hits
}

/// A country typed as a full name ("germany") or a two-letter code.
pub fn parse_name_or_a2(text: &str) -> Option<[u8; 2]> {
    let t = text.trim();
    parse_a2(t).or_else(|| TABLE.iter().find(|e| e.name.eq_ignore_ascii_case(t)).and_then(|e| parse_a2(e.a2)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_and_name_parse() {
        assert_eq!(search("ger")[0].a2, "DE");
        assert_eq!(search("de")[0].a2, "DE");
        assert!(search("zzzz").is_empty());
        assert_eq!(parse_name_or_a2("germany"), Some(*b"DE"));
        assert_eq!(parse_name_or_a2("fr"), Some(*b"FR"));
        assert_eq!(parse_name_or_a2("Narnia"), None);
    }

    #[test]
    fn lookup_is_case_insensitive() {
        assert_eq!(by_a2(*b"gb").unwrap().a3, "GBR");
        assert!(by_a2(*b"ZZ").is_none());
        assert_eq!(by_a2(*b"AE").unwrap().name, "United Arab Emirates");
        let mut codes: Vec<_> = TABLE.iter().map(|e| e.a2).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), TABLE.len(), "duplicate alpha-2 code");
        assert_eq!(parse_a2("de"), Some(*b"DE"));
        assert_eq!(parse_a2("DEU"), None);
    }
}
