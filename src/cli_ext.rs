/// Our custom cli args extension that adds one flag to reth default CLI.
#[derive(Debug, Clone, Copy, Default, clap::Args)]
pub struct ValidationCliExt {
    /// CLI flag to enable the validation extension namespace
    #[clap(long)]
    pub enable_ext: bool,
}
