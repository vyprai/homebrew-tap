class Vyql < Formula
  desc "Multi-language taint and graph security scanner that explains its findings"
  homepage "https://github.com/vyprai/vyql"
  version "0.3.1"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/vyprai/vyql/releases/download/v0.3.1/vyql_v0.3.1_darwin_arm64.tar.gz"
      sha256 "e576e4de5fb3e25133d717d236a696872a9fb9ec0444174b2c024910675a05dd"
    end
    on_intel do
      url "https://github.com/vyprai/vyql/releases/download/v0.3.1/vyql_v0.3.1_darwin_amd64.tar.gz"
      sha256 "68b5f241e4f2674b52f8de804162f00397dd0c0b03406e21decefd40c69d5622"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/vyprai/vyql/releases/download/v0.3.1/vyql_v0.3.1_linux_arm64.tar.gz"
      sha256 "1269459f897578040e4f655c31e16f2758a6e678e7c101b87dd70cad550f02dc"
    end
    on_intel do
      url "https://github.com/vyprai/vyql/releases/download/v0.3.1/vyql_v0.3.1_linux_amd64.tar.gz"
      sha256 "cc906f24fb6fdee15a38b60afb2417b4fdd0bbc2811b44fb93e0c08dc489e97c"
    end
  end

  # The scanner reads its security knowledge from a `vyql/` directory at run
  # time, and finds it by walking up from the resolved path of its own
  # executable. Keeping the binary and that directory together under libexec
  # preserves the relationship; `bin/vyql` is a symlink into it, which resolves
  # back to libexec before the search starts.
  def install
    libexec.install Dir["*"]
    bin.install_symlink libexec/"bin/vyql"
  end

  test do
    assert_match "vyql v#{version}", shell_output("#{bin}/vyql version")

    # Run from a directory with no `vyql/` above it, so the data can only be
    # found by resolving the symlink in bin. This is the failure mode that
    # makes a packaged install panic rather than scan.
    (testpath/"app.py").write <<~PYTHON
      import sqlite3

      def handler(req):
          cur = sqlite3.connect("app.db").cursor()
          cur.execute("SELECT * FROM t WHERE a = '" + req.args.get("a") + "'")
    PYTHON

    # A met -fail-on threshold exits 3: the check ran and did not pass. 1 means
    # vyql could not run and 2 means the invocation was wrong, so a packaging
    # fault cannot be mistaken here for the finding this fixture plants.
    output = shell_output("#{bin}/vyql scan #{testpath}", 3)
    assert_match "finding(s)", output

    # The same scan with the gate off exits 0.
    system bin/"vyql", "scan", "-fail-on", "none", testpath
  end
end
