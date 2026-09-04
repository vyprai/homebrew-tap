class Vyql < Formula
  desc "Multi-language taint and graph security scanner that explains its findings"
  homepage "https://github.com/vyprai/vyql"
  version "0.4.2"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/vyprai/vyql/releases/download/v0.4.2/vyql_v0.4.2_darwin_arm64.tar.gz"
      sha256 "8f02f6e00510dea68f1eda7b339e66215b6553cbbfe745acfc133704246a8720"
    end
    on_intel do
      url "https://github.com/vyprai/vyql/releases/download/v0.4.2/vyql_v0.4.2_darwin_amd64.tar.gz"
      sha256 "456479cc328d76457f29e46635b04f8141b14d37ffcaee870b9e224b047faa55"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/vyprai/vyql/releases/download/v0.4.2/vyql_v0.4.2_linux_arm64.tar.gz"
      sha256 "f5003d87fbada7b8e662be1e1ac451cb9296763b3f7dd9190972a09dec6078fc"
    end
    on_intel do
      url "https://github.com/vyprai/vyql/releases/download/v0.4.2/vyql_v0.4.2_linux_amd64.tar.gz"
      sha256 "8a9d9b3a3d75c65d7a1e6d51330df1622a885034671a2698cb184497af308e52"
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
