class Vyql < Formula
  desc "Multi-language taint and graph security scanner that explains its findings"
  homepage "https://github.com/vyprai/vyql"
  version "0.4.3"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/vyprai/vyql/releases/download/v0.4.3/vyql_v0.4.3_darwin_arm64.tar.gz"
      sha256 "be66199ba3d6e92c8cf67734a16118cc4d5911bccdd5a2e0f486e832dfcb0e43"
    end
    on_intel do
      url "https://github.com/vyprai/vyql/releases/download/v0.4.3/vyql_v0.4.3_darwin_amd64.tar.gz"
      sha256 "090138e267c173c1ae323b0369cf34227156da5898b22b3d7de6a0bb3f4de52c"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/vyprai/vyql/releases/download/v0.4.3/vyql_v0.4.3_linux_arm64.tar.gz"
      sha256 "df382a3b3549ecad47875e6f5078176ac0d74d404c5870131c81b3ea6432493c"
    end
    on_intel do
      url "https://github.com/vyprai/vyql/releases/download/v0.4.3/vyql_v0.4.3_linux_amd64.tar.gz"
      sha256 "6a37c8e0875c78678512abf5ad0ae05d3c44b85911946b53b531dc7da0fef8c6"
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
