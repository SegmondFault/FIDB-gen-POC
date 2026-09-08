import shutil
import tempfile
import tomllib
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from fidb_poc.config import (
    RecipesNotFoundError,
    load_configuration,
)


class ConfigurationTests(unittest.TestCase):
    def test_repository_configuration_is_valid(self):
        root = Path(__file__).resolve().parents[1]
        configuration = load_configuration(root / "worker.toml")
        self.assertEqual(
            [row.identifier for row in configuration.libraries],
            ["zlib-1.3.1", "bzip2-1.0.7"],
        )
        self.assertEqual(len(configuration.routes), 19)
        self.assertEqual(
            {
                route.id
                for route in configuration.routes
                if route.toolchain_state == "qualified"
            },
            {
                "android-arm64-ndk-r27d-clang-api21",
                "android-arm32-ndk-r27d-clang-api21",
                "android-x86-64-ndk-r27d-clang-api21",
                "android-x86-32-ndk-r27d-clang-api21",
                "android-arm64-ndk-r29-clang-api21",
                "android-arm32-ndk-r29-clang-api21",
                "android-x86-64-ndk-r29-clang-api21",
                "android-x86-32-ndk-r29-clang-api21",
                "linux-x86-64-gcc",
                "windows-x86-64-llvm-mingw",
                "linux-arm32-gcc",
                "linux-aarch64-gcc",
                "linux-mips32-be-gcc",
                "linux-mips32-le-gcc",
                "linux-powerpc32-be-gcc",
                "linux-sh32-gcc",
                "linux-m68k-gcc",
            },
        )
        gcc_route = configuration.routes[0]
        self.assertEqual(gcc_route.target_os, "linux")
        self.assertEqual(gcc_route.architecture, "x86_64")
        self.assertEqual(gcc_route.binary_format, "ELF")
        self.assertEqual(gcc_route.compiler_family, "gcc")
        self.assertEqual(gcc_route.compiler, ("/usr/bin/gcc",))
        self.assertEqual(gcc_route.archiver, ("/usr/bin/ar",))
        self.assertEqual(gcc_route.ranlib, ("/usr/bin/ranlib",))
        self.assertEqual(
            gcc_route.compiler_version_markers,
            ("Free Software Foundation",),
        )
        self.assertIn("-fPIC", gcc_route.compiler_flags)
        self.assertNotIn("-g", gcc_route.compiler_flags)
        self.assertEqual(len(configuration.treatments), 6)
        self.assertEqual(
            configuration.treatments[0].description,
            "O2, compiled without -g or LTO, frame pointer retained",
        )
        self.assertEqual(configuration.profiles["smoke"], ("baseline_o2",))
        self.assertEqual(len(configuration.profiles["c-route-toolchain-canary-v1"]), 6)

        android_x86 = [
            route
            for route in configuration.routes
            if route.id.startswith("android-x86")
        ]
        self.assertEqual(len(android_x86), 4)
        self.assertTrue(
            all(route.ghidra_compiler_spec == "gcc" for route in android_x86)
        )

        managed = next(
            row for row in configuration.routes if row.id == "linux-aarch64-gcc"
        )
        self.assertEqual(managed.managed_toolchain_route, managed.id)
        self.assertTrue(managed.toolchain_identity.startswith("qualified:"))
        self.assertTrue(Path(managed.compiler[0]).is_absolute())

    def test_managed_routes_do_not_persist_cache_paths(self):
        root = Path(__file__).resolve().parents[1]
        document = tomllib.loads((root / "worker.toml").read_text(encoding="utf-8"))
        managed = [
            row for row in document["routes"] if "managed_toolchain_route" in row
        ]

        self.assertEqual(len(managed), 17)
        for row in managed:
            self.assertNotIn("compiler", row)
            self.assertNotIn("archiver", row)
            self.assertNotIn("ranlib", row)

    def test_managed_routes_share_one_catalog_load(self):
        root = Path(__file__).resolve().parents[1]
        from fidb_poc.toolchain_packs import load_toolchain_pack_catalog

        with patch(
            "fidb_poc.toolchain_packs.load_toolchain_pack_catalog",
            wraps=load_toolchain_pack_catalog,
        ) as load_catalog:
            configuration = load_configuration(root / "worker.toml")

        self.assertGreater(
            sum(
                route.managed_toolchain_route is not None
                for route in configuration.routes
            ),
            1,
        )
        load_catalog.assert_called_once_with(root)

    def test_work_request_contains_library_names_not_source_details(self):
        root = Path(__file__).resolve().parents[1]
        document = tomllib.loads((root / "worker.toml").read_text())
        self.assertEqual(document["requested_libraries"], ["zlib@1.3.1", "bzip2@1.0.7"])
        self.assertNotIn("url", document)
        self.assertNotIn("sources", document)

    def test_recipes_describe_detection_not_translation_units(self):
        root = Path(__file__).resolve().parents[1]
        recipe = tomllib.loads((root / "recipes/zlib.toml").read_text())
        self.assertEqual(recipe["preferred_build_system"], "autoconf")
        self.assertEqual(recipe["static_archives"], ["libz.a"])
        self.assertNotIn("sources", recipe)
        self.assertNotIn("command", recipe)

    def test_command_line_request_override_resolves_one_recipe(self):
        root = Path(__file__).resolve().parents[1]
        configuration = load_configuration(
            root / "worker.toml", request_override=("zlib@1.3.1",)
        )
        self.assertEqual(
            [row.identifier for row in configuration.libraries],
            ["zlib-1.3.1"],
        )

    def test_multiple_recipe_versions_require_an_exact_request(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            checkout = Path(temporary)
            shutil.copy(root / "worker.toml", checkout / "worker.toml")
            shutil.copytree(root / "recipes", checkout / "recipes")
            old = checkout / "recipes/bzip2.toml"
            new = checkout / "recipes/bzip2-1.0.8.toml"
            new.write_text(
                old.read_text(encoding="utf-8")
                .replace('version = "1.0.7"', 'version = "1.0.8"')
                .replace(
                    'source_directory = "bzip2-1.0.7"',
                    'source_directory = "bzip2-1.0.8"',
                )
                .replace(
                    "e768a87c5b1a79511499beb41500bcc4caf203726fff46a6f5f9ad27fe08ab2b",
                    "ab5a03176ee106d3f0fa90e381da478ddae405918153cca248e682cd0c4a2269",
                ),
                encoding="utf-8",
            )

            with self.assertRaises(RecipesNotFoundError):
                load_configuration(
                    checkout / "worker.toml", request_override=("bzip2",)
                )
            exact = load_configuration(
                checkout / "worker.toml", request_override=("bzip2@1.0.8",)
            )

        self.assertEqual(exact.libraries[0].identifier, "bzip2-1.0.8")

    def test_openssl_recipe_is_pinned_and_static(self):
        root = Path(__file__).resolve().parents[1]
        configuration = load_configuration(
            root / "worker.toml", request_override=("openssl@3.5.8",)
        )

        recipe = configuration.libraries[0]
        self.assertEqual(recipe.name, "openssl")
        self.assertEqual(recipe.preferred_build_system, "openssl-configure")
        self.assertEqual(recipe.static_archives, ("libcrypto.a", "libssl.a"))

    def test_top_ten_recipe_pins_match_the_source_pack(self):
        root = Path(__file__).resolve().parents[1]
        source_pack = tomllib.loads(
            (root / "sources/c-top10-v1.toml").read_text(encoding="utf-8")
        )

        for source in source_pack["source"]:
            configuration = load_configuration(
                root / "worker.toml",
                request_override=(f'{source["id"]}@{source["version"]}',),
            )
            recipe = configuration.libraries[0]
            self.assertEqual(recipe.url, source["url"])
            self.assertEqual(recipe.sha256, source["sha256"])
            self.assertEqual(recipe.source_directory, source["source_directory"])

    def test_dependency_free_c11_c20_recipe_pins_match_the_source_pack(self):
        root = Path(__file__).resolve().parents[1]
        source_pack = tomllib.loads(
            (root / "sources/c-top20-v1.toml").read_text(encoding="utf-8")
        )
        authored = {
            "harfbuzz",
            "freetype",
            "expat",
            "brotli",
            "libjpeg-turbo",
            "libunistring",
            "bzip2",
            "libtiff",
        }

        for source in source_pack["source"]:
            if source["id"] not in authored:
                continue
            configuration = load_configuration(
                root / "worker.toml",
                request_override=(f'{source["id"]}@{source["version"]}',),
            )
            recipe = configuration.libraries[0]
            self.assertEqual(recipe.url, source["url"])
            self.assertEqual(recipe.sha256, source["sha256"])
            self.assertEqual(recipe.source_directory, source["source_directory"])

    def test_dependency_free_c21_c30_recipe_pins_match_the_source_pack(self):
        root = Path(__file__).resolve().parents[1]
        source_pack = tomllib.loads(
            (root / "sources/c-top30-v1.toml").read_text(encoding="utf-8")
        )
        authored = {"zlib", "libffi", "libxml2", "libuv", "openjpeg", "opus"}

        for source in source_pack["source"][20:]:
            if source["id"] not in authored:
                continue
            configuration = load_configuration(
                root / "worker.toml",
                request_override=(f'{source["id"]}@{source["version"]}',),
            )
            recipe = configuration.libraries[0]
            self.assertEqual(recipe.url, source["url"])
            self.assertEqual(recipe.sha256, source["sha256"])
            self.assertEqual(recipe.source_directory, source["source_directory"])

    def test_libpng_recipe_pins_its_route_matched_zlib_input(self):
        root = Path(__file__).resolve().parents[1]
        configuration = load_configuration(
            root / "worker.toml", request_override=("libpng@1.6.58",)
        )

        recipe = configuration.libraries[0]
        self.assertEqual(recipe.preferred_build_system, "libpng-cmake")
        self.assertEqual(recipe.static_archives, ("libpng16.a",))
        self.assertEqual(len(recipe.build_inputs), 1)
        zlib = recipe.build_inputs[0]
        self.assertEqual(zlib.kind, "source-tree")
        self.assertEqual(zlib.identifier, "zlib-1.3.1")
        self.assertEqual(
            zlib.sha256,
            "9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23",
        )

    def test_glib_recipe_pins_every_offline_wrap_input(self):
        root = Path(__file__).resolve().parents[1]
        configuration = load_configuration(
            root / "worker.toml", request_override=("glib@2.88.3",)
        )

        recipe = configuration.libraries[0]
        self.assertEqual(recipe.preferred_build_system, "glib-meson")
        self.assertEqual(len(recipe.build_inputs), 7)
        self.assertEqual(
            {row.filename for row in recipe.build_inputs},
            {
                "pcre2-10.46.tar.bz2",
                "pcre2_10.46-1_patch.zip",
                "libffi-3.5.2.tar.gz",
                "libffi_3.5.2-1_patch.zip",
                "zlib-1.3.1.tar.gz",
                "zlib_1.3.1-1_patch.zip",
                "proxy-libintl-0.5.tar.gz",
            },
        )

    def test_unknown_library_request_fails_closed(self):
        root = Path(__file__).resolve().parents[1]
        with self.assertRaisesRegex(ValueError, "no approved recipe"):
            load_configuration(
                root / "worker.toml", request_override=("imaginary-lib",)
            )

    def test_recipe_applicability_is_explicit_and_route_aware(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            checkout = Path(temporary)
            shutil.copy(root / "worker.toml", checkout / "worker.toml")
            shutil.copytree(root / "recipes", checkout / "recipes")
            recipe_path = checkout / "recipes/zlib-1.3.2.toml"
            recipe_path.write_text(
                recipe_path.read_text(encoding="utf-8")
                + '\nsupported_target_os = ["linux"]\n'
                + 'supported_architectures = ["x86_64"]\n'
                + 'supported_compiler_families = ["gcc"]\n',
                encoding="utf-8",
            )
            configuration = load_configuration(
                checkout / "worker.toml", request_override=("zlib@1.3.2",)
            )

        recipe = configuration.libraries[0]
        self.assertTrue(recipe.applies_to(configuration.routes[0]))
        self.assertFalse(
            recipe.applies_to(replace(configuration.routes[0], target_os="windows"))
        )

    def test_all_unknown_library_requests_are_reported(self):
        root = Path(__file__).resolve().parents[1]
        with self.assertRaises(RecipesNotFoundError) as raised:
            load_configuration(
                root / "worker.toml",
                request_override=("imaginary-one", "imaginary-two"),
            )
        self.assertEqual(raised.exception.requests, ("imaginary-one", "imaginary-two"))

    def test_duplicate_routes_are_rejected(self):
        root = Path(__file__).resolve().parents[1]
        text = (root / "worker.toml").read_text(encoding="utf-8")
        text = text.replace(
            'recipe_directory = "recipes"',
            f'recipe_directory = "{root / "recipes"}"',
        )
        route_start = text.index("[[routes]]")
        treatment_start = text.index("[[treatments]]")
        route_block = text[route_start:treatment_start]
        text = text[:treatment_start] + route_block + text[treatment_start:]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "config.toml"
            path.write_text(text, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "route ids must be unique"):
                load_configuration(path)

    def test_generated_path_components_cannot_escape_the_project(self):
        root = Path(__file__).resolve().parents[1]
        text = (root / "worker.toml").read_text(encoding="utf-8")
        text = text.replace(
            'recipe_directory = "recipes"',
            f'recipe_directory = "{root / "recipes"}"',
        ).replace('id = "linux-x86_64-gnu-gcc"', 'id = "../../src"')
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "config.toml"
            path.write_text(text, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "route id must be a safe"):
                load_configuration(path)

    def test_unknown_worker_fields_fail_closed(self):
        root = Path(__file__).resolve().parents[1]
        text = (root / "worker.toml").read_text(encoding="utf-8")
        text = text.replace("[[routes]]", "unexpected = true\n\n[[routes]]", 1)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "config.toml"
            path.write_text(text, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unknown fields"):
                load_configuration(path)

    def test_old_worker_schema_is_rejected(self):
        root = Path(__file__).resolve().parents[1]
        text = (root / "worker.toml").read_text(encoding="utf-8")
        text = text.replace("fidb-worker/v3", "fidb-worker/v2", 1)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "config.toml"
            path.write_text(text, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "schema_version"):
                load_configuration(path)

    def test_recipe_path_components_cannot_escape_the_source_root(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            checkout = Path(temporary)
            shutil.copy(root / "worker.toml", checkout / "worker.toml")
            shutil.copytree(root / "recipes", checkout / "recipes")
            recipe_path = checkout / "recipes/zlib.toml"
            text = recipe_path.read_text(encoding="utf-8")
            text = text.replace(
                'source_directory = "zlib-1.3.1"',
                'source_directory = "../../src"',
            )
            recipe_path.write_text(text, encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "source_directory must be a safe"):
                load_configuration(checkout / "worker.toml")

    def test_programmatic_configuration_rejects_unsafe_generated_components(self):
        root = Path(__file__).resolve().parents[1]
        configuration = load_configuration(root / "worker.toml")

        with self.assertRaisesRegex(ValueError, "route id must be a safe"):
            replace(configuration.routes[0], id="../../src")
        with self.assertRaisesRegex(ValueError, "treatment id must be a safe"):
            replace(configuration.treatments[0], id="../output")
        with self.assertRaisesRegex(ValueError, "library name must be a safe"):
            replace(configuration.libraries[0], name="/tmp/escape")


if __name__ == "__main__":
    unittest.main()
