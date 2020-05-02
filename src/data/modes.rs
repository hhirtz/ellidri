use ellidri_tokens::mode;

#[derive(Clone, Copy, Debug)]
pub struct Channel<'a>(&'a str, &'a [&'a str]);

impl<'a> Channel<'a> {
    pub fn new(modes: &'a str, params: &'a [&'a str]) -> Self {
        Self(modes, params)
    }

    pub fn iter(&self) -> impl Iterator<Item = mode::Result<mode::ChannelChange<'a>>> {
        mode::channel_query(self.0, self.1)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct User<'a>(&'a str);

impl<'a> User<'a> {
    pub fn new(modes: &'a str) -> Self {
        Self(modes)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = mode::Result<mode::UserChange>> + 'a {
        mode::user_query(self.0)
    }
}
