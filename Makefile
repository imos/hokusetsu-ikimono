.PHONY: archive
.PHONY: ashitaka
.PHONY: publish

archive:
	python3 scripts/archive_wayback.py

ashitaka:
	python3 scripts/archive_wayback.py --domain http://www.wombat.zaq.ne.jp/ashitaka/ --output ashitaka_html --before 2010-12-01

publish:
	python3 scripts/publish.py
