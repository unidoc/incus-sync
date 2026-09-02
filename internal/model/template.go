package model

// Template is a bastille-style provisioning bundle: an optional pre-hook,
// a directory tree of files to copy into the container, and an optional
// post-hook. Applied ONLY at container create time, in the order the
// instance lists them.
//
// Layout on disk:
//
//	<fleet-repo>/templates/<name>/
//	  manifest.yaml   (optional — describes the template + file modes)
//	  before.sh       (optional — runs BEFORE files/ tar-push)
//	  files/          (optional — tree copied 1:1 into container root)
//	  after.sh        (optional — runs AFTER files/ tar-push)
//
// Execution order per template: before.sh → tar-push files/ → after.sh.
// Use before.sh to install packages so their post-install ownership on
// standard paths (like /etc/ssh) is already correct when files/ overlays
// its content.
//
// Files map declares per-path mode overrides. Anything not listed
// defaults to 0644 for regular files and 0755 for directories. Owner
// is always root:root (host filesystem uids are meaningless inside the
// container).
//
// No variable substitution, no inheritance, no conditionals.
type Template struct {
	Name        string `yaml:"template"`
	Description string `yaml:"description,omitempty"`

	// Secrets is the list of key-value secrets this template needs
	// injected into its before.sh / after.sh as environment variables.
	// Values are looked up from shared/secrets.sops.yaml at apply time
	// (SOPS-encrypted, unlocked via the same age key as remotes).
	//
	// Example:
	//   secrets:
	//     - env: AHALL_PASSWORD_HASH
	//       from: alice.password_hash
	//     - env: NGINX_HTPASSWD
	//       from: nginx.htpasswd
	//
	// Not listed as YAML struct: templates typically declare zero or a
	// small handful. Missing paths produce a hard failure at plan time
	// (fail early rather than silently apply a template with empty
	// secrets that were supposed to be set).
	Secrets []SecretRef `yaml:"secrets,omitempty"`

	// Files maps absolute paths (matching the files/ tree structure) to
	// per-file overrides for owner, group, and mode.
	//
	// Defaults when a path is not listed (or a field omitted):
	//   owner: root
	//   group: root
	//   mode:  0644 for regular files, 0755 for directories
	//
	// Named owner/group is resolved by tar-extract inside the container
	// via getpwnam/getgrnam. That means the user/group must already exist
	// at tar-push time — declare it in the template's before.sh (which
	// runs first). If lookup fails, tar falls back to uid/gid 0 (root),
	// which is almost never what you want, so the loader can be extended
	// later to fail-fast on missing before.sh + non-root ownership.
	//
	// Example:
	//   files:
	//     /etc/sudoers.d/wheel:           { mode: "0440" }
	//     /home/alice:                    { owner: alice, group: alice, mode: "0700" }
	//     /home/alice/.ssh:               { owner: alice, group: alice, mode: "0700" }
	//     /home/alice/.ssh/authorized_keys: { owner: alice, group: alice, mode: "0600" }
	Files map[string]TemplateFileMeta `yaml:"files,omitempty"`

	// Path is the on-disk directory, populated by the loader.
	Path string `yaml:"-"`
}

// TemplateFileMeta declares per-file metadata inside a template's manifest.
// Empty string for any field means "use default" — see Template.Files docs.
type TemplateFileMeta struct {
	Owner string `yaml:"owner,omitempty"`
	Group string `yaml:"group,omitempty"`
	Mode  string `yaml:"mode,omitempty"`
}

// SecretRef binds a fleet secret (looked up in shared/secrets.sops.yaml
// by dotted path) to an environment variable in the template's shell
// scripts.
type SecretRef struct {
	Env  string `yaml:"env"`  // env var name, e.g. AHALL_PASSWORD_HASH
	From string `yaml:"from"` // dotted path, e.g. alice.password_hash
}
