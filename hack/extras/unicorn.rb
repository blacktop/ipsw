class Unicorn < Formula
  desc "Lightweight multi-architecture CPU emulation framework"
  homepage "https://www.unicorn-engine.org/"
  head "https://github.com/unicorn-engine/unicorn.git", branch: "dev"

  depends_on "pkg-config" => :build
  depends_on "python@3.10" => [:build, :test]

  def install
    ENV["PREFIX"] = prefix
    ENV["UNICORN_ARCHS"] = "aarch64"
    ENV["UNICORN_SHARED"] = "yes"
    ENV["UNICORN_DEBUG"] = "no"
    system "make"
    system "make", "install"

    cd "bindings/python" do
      system Formula["python@3.10"].opt_bin/"python3", *Language::Python.setup_install_args(prefix)
    end
  end
end