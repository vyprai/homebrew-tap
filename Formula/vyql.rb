class Vyql < Formula
  desc "Multi-language taint and graph security scanner that explains its findings"
  homepage "https://github.com/vyprai/vyql"
  version "0.5.0"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/vyprai/vyql/releases/download/v0.5.0/vyql_v0.5.0_darwin_arm64.tar.gz"
      sha256 "13f14d42b3010ac5c6cdb1f4e466d60c0624c9740a96e24c794f064f1d36a5a7"
    end
    on_intel do
      url "https://github.com/vyprai/vyql/releases/download/v0.5.0/vyql_v0.5.0_darwin_amd64.tar.gz"
      sha256 "3e4343fb2be9b2d5a888834c119650c2a7bfcd688914d736af98fddb836cddc6"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/vyprai/vyql/releases/download/v0.5.0/vyql_v0.5.0_linux_arm64.tar.gz"
      sha256 "1bb8ececce3cb3ea0421e483f25c35f6acaf460b74c4aacda8145a9e5cd117ca"
    end
    on_intel do
      url "https://github.com/vyprai/vyql/releases/download/v0.5.0/vyql_v0.5.0_linux_amd64.tar.gz"
      sha256 "94a5259c1144f674bab2e136a193eee0fe0645de17bc22fa5284b46b4ebe1088"
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
