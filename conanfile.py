from conan import ConanFile
from conan.tools.cmake import CMake, CMakeToolchain, cmake_layout
from conan.tools.files import copy
import os

class Blake3PlusConan(ConanFile):
    name = "blake3plus"
    version = "1.8.7"
    description = "BLAKE3 cryptographic hash with native C11 pthread work-stealing, cgroup detection, and memory protection"
    license = ("CC0-1.0", "Apache-2.0")
    url = "https://github.com/trishaRonix/BLAKE3PLUS"
    topics = ("crypto", "hash", "blake3", "multithreading", "c11")
    settings = "os", "arch", "compiler", "build_type"
    options = {
        "shared": [True, False],
        "fPIC": [True, False],
        "with_pthread": [True, False],
    }
    default_options = {
        "shared": False,
        "fPIC": True,
        "with_pthread": True,
    }

    def config_options(self):
        if self.settings.os == "Windows":
            del self.options.fPIC

    def layout(self):
        cmake_layout(self, src_folder="c")

    def generate(self):
        tc = CMakeToolchain(self)
        tc.variables["BLAKE3PLUS_ENABLE_PTHREAD"] = self.options.with_pthread
        tc.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        copy(self, "blake3.h", src=self.source_folder, dst=os.path.join(self.package_folder, "include"))
        copy(self, "blake3plus.h", src=self.source_folder, dst=os.path.join(self.package_folder, "include"))
        copy(self, "*.a", src=self.build_folder, dst=os.path.join(self.package_folder, "lib"), keep_path=False)
        copy(self, "*.so*", src=self.build_folder, dst=os.path.join(self.package_folder, "lib"), keep_path=False)
        copy(self, "*.dylib*", src=self.build_folder, dst=os.path.join(self.package_folder, "lib"), keep_path=False)
        copy(self, "*.lib", src=self.build_folder, dst=os.path.join(self.package_folder, "lib"), keep_path=False)
        copy(self, "*.dll", src=self.build_folder, dst=os.path.join(self.package_folder, "bin"), keep_path=False)

    def package_info(self):
        self.cpp_info.libs = ["blake3"]
        if self.options.with_pthread:
            self.cpp_info.defines.append("BLAKE3PLUS_ENABLE_PTHREAD")
            if self.settings.os in ["Linux", "FreeBSD"]:
                self.cpp_info.system_libs.extend(["pthread", "m"])
