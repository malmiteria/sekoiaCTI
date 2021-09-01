install-virtualenv:
	rd local.virtualenv 2>nul &
	python3 -m virtualenv -p python3.8 local.virtualenv
	local.virtualenv\Scripts\activate
	local.virtualenv\Scripts\pip install setuptools pip wheel -U
	local.virtualenv\Scripts\pip install -r requirements.txt --find-links "file://${HOME}/.pip/wheelhouse"

run:
	local.virtualenv\Scripts\python -u -m threat_finder
