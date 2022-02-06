#! /usr/bin/env python3

import json, sys

def err(s, end='\n'):
    print(s, file=sys.stderr, end=end)
    
if len(sys.argv) != 4:
    err("Usage: %s <inputs> <expected> <submitted>" % sys.argv[0])
    sys.exit(1)

with open(sys.argv[1]) as f:
    inputs_json = json.load(f)

with open(sys.argv[2]) as f:
    expected_json = json.load(f)

with open(sys.argv[3]) as f:
    submitted_json = json.load(f)

assert type(inputs_json) == dict, "inputs is not a dictionary"
assert type(expected_json) == dict, "expected items not in a dictionary"
assert type(submitted_json) == dict, "submitted json not a dictionary"

problem_objects = []


def grade_prob_4(student_answers):
    score = 0
    queries = inputs_json["problem 4"]
    
    n = len(queries)
    results = student_answers

    while len(results) != n:
        results.append(-1)

    for i in range(n):
        if (results[i] < queries[i]) and results[i] >= 0:
            err("\tPart %d: correct (pending manual review)" % (i + 1))
            score = score + 1
        else:
            err("\tPart %d incorrect" % (i + 1))
    return score
            
    
for problem, problem_key in expected_json.items():
    problem_object = {"name" : problem, "max_score" : len(problem_key), "score" : 0}
    problem_objects.append(problem_object)
    
    err("%s: " % problem)
    
    if problem not in submitted_json:
        err("\tNot provided.")
        continue

    student_answers = submitted_json[problem]

    n = len(problem_key)

    assert type(problem_key) == list, "Answer key is not a list!"

    if type(student_answers) != list:
        err("\tAnswers to the problem are not in a list.")
        continue
    
    if len(student_answers) != n:
        if len(student_answers) < n:
            err("\tToo few answers for problem.")
            n = len(student_answers)
        else:
            err("\tMore answers submitted then tests.")

    if problem == "problem 4":
        problem_object["score"] += grade_prob_4(student_answers)
        continue
            
    for i in range(n):
        right = False
        if type(problem_key[i]) == str:
            if student_answers[i].upper().strip() == problem_key[i].upper().strip():
                right = True
        elif student_answers[i] == problem_key[i]:
            right = True
            
        if right:
            err("\tPart %d: correct" % (i + 1))
            problem_object["score"] += 1
        else:
            err("\tPart %d: incorrect" % (i + 1))
            

output = { "stdout_visibility" : "visible",
           "tests" : problem_objects,
           "output" : "Thanks for submitting. Remember that you can re-submit as many times as you like!"
           
}

json.dump(output, sys.stdout, indent = "  ")
print()
