use std::collections::HashSet;

pub struct SSRFDefense {
    approved_domains: HashSet<String>,
}

impl SSRFDefense {
    pub fn new_with_defaults() -> Self {
        let mut domains = HashSet::new();
        domains.insert("api.openai.com".into());
        domains.insert("api.anthropic.com".into());
        Self {
            approved_domains: domains,
        }
    }

    pub fn approve_domain(&mut self, domain: &str) {
        self.approved_domains.insert(domain.into());
    }

    pub fn validate_upstream(&self, _url: &str) -> Result<(), String> {
        // Stub validation
        Ok(())
    }
}
