SHELL=bash
.SECONDARY:

clean:
	-rm */ps*
	-rm */*.sh

%.json:
	curl -Ls https://raw.githubusercontent.com/viega/applied_crypto_2022_spring/master/$(dir $*)/$(notdir $*).json > $@

%/setup.sh: setup.sh
	cp setup.sh $*/setup.sh

%/bin:
	cp $*/__init__.py $*/$*
	chmod +x $*/$*

%/solution-diff-example: %/example-input.json %/example-output.json
	colordiff -u \
		<(cat $*/example-input.json | python $*/__init__.py) \
		<(cat $*/example-output.json | python -m json.tool)

%/solution-diff-expected:
	colordiff -u \
		<(cat $*/grader/test-inputs.json | python $*/__init__.py) \
		<(cat $*/grader/test-expected.json | python -m json.tool)

%/solution-grade-example: %/example-input.json %/example-output.json
	python \
		$*/grader/grade.py \
		$*/example-input.json \
		$*/example-output.json \
		<(cat $*/example-input.json | python $*/__init__.py)

%/solution-grade-expected:
	python \
		$*/grader/grade.py \
		$*/grader/test-inputs.json \
		$*/grader/test-expected.json \
		<(cat $*/grader/test-inputs.json | python $*/__init__.py)

%/solution-grade:
	cp $*/__init__.py $*/grader/$*
	chmod +x $*/grader/$*
	cd $*/grader && python grader.py

%/diff-example: %/example-input.json %/example-output.json
	colordiff -u \
		<(cat $*/example-input.json | python <(pbpaste) | python -m json.tool) \
		<(cat $*/example-output.json | python -m json.tool)

%/diff-expected:
	colordiff -u \
		<(cat $*/grader/test-inputs.json | python <(pbpaste) | python -m json.tool)\
		<(cat $*/grader/test-expected.json | python -m json.tool)

%/grade-example:
	python \
		$*/grader/grade.py \
		$*/example-input.json \
		$*/example-output.json \
		<(cat $*/example-input.json | python <(pbpaste))

%/grade-expected:
	python \
		$*/grader/grade.py \
		$*/grader/test-inputs.json \
		$*/grader/test-expected.json \
		<(cat $*/grader/test-inputs.json | python <(pbpaste))

%/grade:
	pbpaste > $*/grader/$*
	chmod +x $*/grader/$*
	cd $*/grader && python grader.py
