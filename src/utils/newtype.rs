#[macro_export]
macro_rules! newtype {
    {
        $(#[$attr:meta])*
        $vis:vis $ty_name:ident($vis_inner:vis $ty_inner:ty)$(;)?
    } => {
        $(#[$attr])*
        #[derive(
            Clone,
            Copy,
            Serialize,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            ::derive_more::Deref,
            ::derive_more::DerefMut,
            ::derive_more::From,
            ::derive_more::Into
        )]
        #[serde(transparent)]
        $vis struct $ty_name($vis_inner $ty_inner);
    };
}
