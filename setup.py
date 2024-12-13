# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2020-2022 Regione Piemonte
# (C) Copyright 2018-2024 CSI-Piemonte

from setuptools import setup
from setuptools.command.install import install as _install


class install(_install):
    def pre_install_script(self):
        pass

    def post_install_script(self):
        pass

    def run(self):
        self.pre_install_script()

        _install.run(self)

        self.post_install_script()


def load_requires():
    with open("./MANIFEST.md") as f:
        requires = f.read()
    return requires


def load_version():
    with open("./beehive_service_netaas/VERSION") as f:
        version = f.read()
    return version


if __name__ == "__main__":
    version = load_version()
    setup(
        name="beehive_service_netaas",
        version=version,
        description="Utility",
        long_description="Utility",
        author="CSI Piemonte",
        author_email="nivola.engineering@csi.it",
        license="EUPL-1.2",
        url="",
        scripts=[],
        packages=[
            "beehive_service_netaas",
            "beehive_service_netaas.networkservice",
            "beehive_service_netaas.networkservice.views",
        ],
        namespace_packages=[],
        py_modules=["beehive_service_netaas.__init__"],
        classifiers=[
            "Development Status :: %s" % version,
            "Programming Language :: Python",
        ],
        entry_points={},
        data_files=[],
        package_data={"beehive_service_netaas": ["VERSION"]},
        install_requires=load_requires(),
        dependency_links=[],
        zip_safe=True,
        cmdclass={"install": install},
        keywords="",
        python_requires="",
        obsoletes=[],
    )
