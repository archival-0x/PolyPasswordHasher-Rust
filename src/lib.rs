extern crate ring;

mod shamirsecret;

pub struct PolyPasswordHasher {
    accountdict: Option<String>,
    shamirsecretobj: Option<ShamirSecret>,
    knownsecret: bool,
    saltsize: u8,
    hasher: // TODO: AES type
    serializer: // TODO: Serializer type
    partialbytes: u8,
    thresholdsecretkey: Option<>,
    nextavailableshare: u8
}

impl Default for PolyPasswordHasher {
    fn default() -> PolyPasswordHasher {
            
    }
}

impl PolyPasswordHasher {
    pub fn new(threshold: u8, passwordfile: Option<String>, _partialbytes: Option<u8>) -> PolyPasswordHasher {
        
        let mut partialbytes: u8 = 0;
        
        // Provide default case for partialbytes variable
        if let Some(p) = _partialbytes {
            partialbytes = p;
        }
        
        
        
    }
    
}

fn do_bytearray_xor(a, b) {
    if a.len() != b.len() {
        
    }
}
