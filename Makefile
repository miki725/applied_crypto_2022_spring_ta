SHELL=bash
.SECONDARY:

SOURCE_FILES=$(wildcard *.py) $(wildcard Pipfile*) $(wildcard *.sh) run_autograder
PS=$(wildcard ps*)

foo:
	echo $(addsuffix /submission/ps,$(PS))

clean:
	-rm */*/*.zip
	-rm */*/*.log
	-rm */*/_*.json
	-rm -rf **/__pycache__
	-rm */*/results/*
	-rm */submission/ps

copy-%:
	cp $(SOURCE_FILES) $*/source/

copy: $(addprefix copy-,$(PS))

%.json:
	curl -Ls https://raw.githubusercontent.com/viega/applied_crypto_2022_spring/master/$(firstword $(subst /, ,$*))/$(notdir $*).json \
		| python -m json.tool \
		> $@

ifeq "$(PASTE)" "true"
$(shell rm  $(addsuffix /submission/ps,$(PS)) 2> /dev/null)
%/submission/ps:
	pbpaste > $@
	chmod +x $@
else
%/submission/ps: %/source/solution.py
	cp $^ $@
	chmod +x $@
endif

%/diff: %/submission/example-input.json %/submission/example-output.json %/submission/ps
	colordiff -u \
		<(cat $*/submission/example-input.json | ./$*/submission/ps | python -m json.tool) \
		<(cat $*/submission/example-output.json | python -m json.tool)

%/run_autograder: ./run_autograder
	cp $^ $@
	chmod +x $@

%/grade: %/submission/ps %/run_autograder copy
	cd $* && ./run_autograder

%/source/grading.zip: clean copy
	cd $*/source \
		&& zip grading.zip * \
		&& zip -sf grading.zip
