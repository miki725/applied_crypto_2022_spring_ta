SHELL=bash
.SECONDARY:

SOURCE_FILES=$(wildcard *.py) $(wildcard Pipfile*) $(wildcard *.sh) run_autograder
PS=$(wildcard ps*) $(wildcard project*)

clean:
	-rm */*/*.zip
	-rm */*/*.log
	-rm */*/_*.json
	-rm -rf **/__pycache__
	-rm */*/results/*
	-rm */submission/ps*
	-rm */submission/fencrypt

copy-%:
	cp $(SOURCE_FILES) $*/source/

copy: $(addprefix copy-,$(PS))

%.json:
	curl -Ls https://raw.githubusercontent.com/viega/applied_crypto_2022_spring/master/$(firstword $(subst /, ,$*))/$(notdir $*).json \
		| python -m json.tool \
		> $@

ifeq "$(PASTE)" "true"
%/submission/ps:
	source $*/source/config.sh && pbpaste > $(dir $@)$${BIN}
	source $*/source/config.sh && chmod +x $(dir $@)$${BIN}
else
%/submission/ps: %/source/solution.py
	source $*/source/config.sh && cp $^ $(dir $@)$${BIN}
	source $*/source/config.sh && chmod +x $(dir $@)$${BIN}
endif

%/diff: %/submission/example-input.json %/submission/example-output.json %/submission/ps
	colordiff -u \
		<(cat $*/submission/example-input.json | ./$*/submission/ps | python -m json.tool) \
		<(cat $*/submission/example-output.json | python -m json.tool)

%/run_autograder: ./run_autograder
	cp $^ $@
	chmod +x $@

pdb:
	$(eval export PYTEST_FLAGS=$(PYTEST_FLAGS) --pdb)

%/grade: %/submission/ps %/run_autograder copy
	cd $* && ./run_autograder

%/source/grading.zip: clean copy
	cd $*/source \
		&& zip grading.zip * -r -x '*/__pycache__/*' -x '*/.pytest_cache/*' \
		&& zip -sf grading.zip

%/submission/solution.zip: clean copy %/submission/ps
	cd $*/submission \
		&& zip solution.zip * -r -x '*/__pycache__/*' -x '*/.pytest_cache/*' \
		&& zip -sf solution.zip
