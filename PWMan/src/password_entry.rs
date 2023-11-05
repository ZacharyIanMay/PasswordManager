
#[derive(Clone, Debug)]
pub struct PasswordEntry {
    pub site: String,
    pub username: String,
    pub password: String,
}

impl PasswordEntry {
    pub fn serialize(self) -> String {
        format!("{}:{}:{}", self.site, self.username, self.password)
    }

    pub fn deserialize(value: (String, String, String)) -> Self {
        value.into()
    }
}

impl From<String> for PasswordEntry {
    fn from(value: String) -> Self {
        let mut split = value.split(":");
        let site = split.next().unwrap_or("").into();
        let username = split.next().unwrap_or("").into();
        let password = split.next().unwrap_or("").into();
        Self {
            site,
            password,
            username,
        }
    }
}

impl From<(String, String, String)> for PasswordEntry {
    fn from(value: (String, String, String)) -> Self {
        let (site, username, password) = value;
        Self {
            site,
            username,
            password
        }
    }
}
