# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2020-2022 Regione Piemonte
# (C) Copyright 2018-2024 CSI-Piemonte

# __version__ = "1.0.0"

import os.path

version_file = os.path.join(os.path.abspath(__file__).rstrip("__init__.pyc"), "VERSION")
if os.path.isfile(version_file):
    with open(version_file) as version_file:
        __version__ = "%s" % (version_file.read().strip()[:10])

__git_last_commit__ = ""
try:
    import os

    LAST_COMMIT_PATH = os.getenv("LAST_COMMIT_BEEHIVE_SERVICE_NETAAS")
    if LAST_COMMIT_PATH is not None:
        with open(LAST_COMMIT_PATH) as f:
            __git_last_commit__ = f.read()
except Exception as ex:
    print(ex)
    pass
