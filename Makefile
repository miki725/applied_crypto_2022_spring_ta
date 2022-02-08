SHELL=bash
.SECONDARY:

clean:
	rm */*.json

%.json:
	curl -Ls https://raw.githubusercontent.com/viega/applied_crypto_2022_spring/master/$(dir $*)/example-$(notdir $*).json > $@

%/test: %/input.json %/output.json
	colordiff -u <(cat $*/input.json | python $*/solution.py) <(cat $*/output.json | python -m json.tool)

%/test-clip: %/input.json %/output.json
	colordiff -u <(cat $*/input.json | python <(pbpaste) | python -m json.tool) <(cat $*/output.json | python -m json.tool)

%/grade:
	python \
		$*/grader/grade.py \
		$*/grader/test-inputs.json \
		$*/grader/test-expected.json \
		<(cat $*/grader/test-inputs.json | python $*/solution.py)

%/clip:
	python \
		$*/grader/grade.py \
		$*/grader/test-inputs.json \
		$*/grader/test-expected.json \
		<(cat $*/grader/test-inputs.json | python <(pbpaste))
