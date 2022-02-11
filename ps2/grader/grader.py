from Crypto.Cipher import AES
import secrets
import json
import sys
import os
import random


ticker_symbols = ['AAPL', 'MSFT', 'NYUX', 'IDFC', 'WOW!', 'MOM ', 'DADA', 'NONO', 'YADA']

trade_ops      = ['B', 'S']

def format_trade(op, symbol, num):
    s = str(num)
    n = 8 - len(s)
    pad = ' '*n
    
    return bytes('%s %s: %s%s' % (op, symbol, s, pad), encoding='utf8')

def flip_trade_pt(bstr):
    chars = [x for x in bstr]
    chars[0] = chars[0] ^ 17
    return bytes(chars)

def random_trade(max_shares, max_ticker=len(ticker_symbols)):
    op = trade_ops[secrets.randbits(1)]
    co = ticker_symbols[secrets.randbelow(max_ticker)]
    n  = secrets.randbelow(max_shares) + 1

    return format_trade(op, co, n)
    

            

# news_trades will get two values:
# One with a single trade that should be replaced.
# One with a bunch of trades where multiple ones should be replaced
# (but not all).
#
# For the ticker to use as the replacement, we'll pick one that has
# multiple tickers, to make sure they use the one with the highest
# numeric value.
#
# This problem should be worth 3 points... 1 point for the first day,
# 1 point for the second day, and then 1 point for getting the numeric
# value right.
#
# That means we need to be tolerant to them replacing the WRONG block,
# which means the first and second parts have multiple solutions that
# get points.
#
# And the last point they only get if they get the BEST answer for the
# first two.

def create_problem_1_instance():
    k = secrets.token_bytes(16)
    ctx = AES.new(k, AES.MODE_ECB)
    
    old_trades = []

    # There will be 1 to 3 entries for each possible trade.

    ones_with_dupes = []

    for symbol in ticker_symbols:
        for trade_op in trade_ops:
            for i in range(1 + secrets.randbelow(2)):
                if i > 1:
                    ones_with_dupes.append((trade_op, symbol))
                old_trades.append((trade_op,
                                   symbol,
                                   1000 + secrets.randbelow(1000)))

    if not len(ones_with_dupes):
        old_trades.append(('B', 'AAPL', 1000 + secrets.randbelow(1000)))
        ones_with_dupes.append(('B', 'AAPL'))
    random.shuffle(ones_with_dupes)
    info_2 = ones_with_dupes[0]

    random.shuffle(old_trades)


    # info_2 is the one we're replacing WITH, meaning something w/ dupes,
    # so that we can test that they did crap right.
    # It's unlikely but possible that the trade amounts are the same,
    # but whatever.
    while True:
      op = trade_ops[secrets.randbits(1)]
      co = ticker_symbols[secrets.randbelow(len(ticker_symbols))]
      if co != info_2[1]:
          info_1 = (op, co)
          break

    best_replacement_ct = None
    largest = 0
    possible_replacers = {}
    trades_to_target = {}
    decoy_trades = {}
    
    old_pt_b = b''
    for op, ticker, num in old_trades:
        one_pt = format_trade(op, ticker, num)
        one_ct = ctx.encrypt(one_pt)
        if op == info_2[0] and ticker == info_2[1]:
            possible_replacers[one_pt] = one_ct
            if num > largest:
                largest = num
                best_replacement_ct = one_ct
        if op == info_1[0] and ticker == info_1[1]:
            trades_to_target[one_pt] = one_ct
        if op != info_1[0] and ticker == info_1[1]:
            decoy_trades[one_pt] = one_ct
        old_pt_b += one_pt

    ttt = list(trades_to_target.keys())
    random.shuffle(ttt)
    day_one_trades_pt = ttt[0]

    day_two_trade_list = []
    for i in range(secrets.randbelow(3) + 1):
        random.shuffle(ttt)
        day_two_trade_list.append(ttt[0])

    decoy_possibilities = list(decoy_trades.keys())
    random.shuffle(decoy_possibilities)
    day_two_trade_list.append(decoy_possibilities[0])
    
    other_tickers = [x for x in ticker_symbols if x != info_1[1]]
    for i in range(secrets.randbelow(3) + 1):
        random.shuffle(other_tickers)
        co = other_tickers[0]
        op = trade_ops[secrets.randbits(1)]
        n = secrets.randbelow(1000) + 1000
        day_two_trade_list.append(format_trade(op, co, n))

    random.shuffle(day_two_trade_list)

    input_vals = {}

    input_vals['old_pt'] = old_pt_b.hex()
    input_vals['old_ct'] = ctx.encrypt(old_pt_b).hex()
    input_vals['op_1'] = info_1[0]
    input_vals['co_1'] = info_1[1]
    input_vals['op_2'] = info_2[0]
    input_vals['co_2'] = info_2[1]

    new_trades = []
    new_trades.append(ctx.encrypt(day_one_trades_pt).hex())
    new_trades.append(ctx.encrypt(b''.join(day_two_trade_list)).hex())
    input_vals['new_trades'] = new_trades
    
    return k, input_vals, possible_replacers, best_replacement_ct, trades_to_target

def create_problem_2_instance():
    k = secrets.token_bytes(16)
    ctx1 = AES.new(k, AES.MODE_CTR, nonce=b'01234567')
    ctx2 = AES.new(k, AES.MODE_CTR, nonce=b'01234567')    
    n1 = secrets.randbelow(4) + 4  # n is between 4 and 7.
    n2 = secrets.randbelow(n1-2) + 2
    pt1_list = [random_trade(1000) for _ in range(n1)]
    pt2_list = [random_trade(1000) for _ in range(n2)]
    old_pt_b = b''.join(pt1_list)
    old_ct_b = ctx1.encrypt(old_pt_b)
    new_pt_b = b''.join(pt2_list)
    new_ct_b = ctx2.encrypt(new_pt_b)

    input_vals = {
        'old_pt' : old_pt_b.hex(),
        'old_ct' : old_ct_b.hex(),
        'new_ct' : new_ct_b.hex()
        }
    
    return k, input_vals, new_pt_b.hex()
    

def create_problem_3_instance():
    k = secrets.token_bytes(16)
    ctx = AES.new(k, AES.MODE_CTR, nonce=b'11111111')
    mctx = AES.new(k, AES.MODE_CTR, nonce=b'11111111')    
    old_pt = b''
    moded_pt = b''
    
    for i in range(secrets.randbelow(5) + 2):
        op     = trade_ops[secrets.randbits(1)]
        ticker = ticker_symbols[secrets.randbelow(len(ticker_symbols))]
        num    = 500 + secrets.randbelow(1000)
        old_pt += format_trade(op, ticker, num)

        if op == 'B':
            moded_op = 'S'
        else:
            moded_op = 'B'
        moded_pt += format_trade(moded_op, ticker, num)
    todays_ct = ctx.encrypt(old_pt)
    moded_ct  = mctx.encrypt(moded_pt)

    input_vals = { 'todays_ct' : todays_ct.hex() }
    

    return k, input_vals, moded_ct.hex()

    ctx = AES.new(k, AES.MODE_CTR, nonce=b'11111111')
    munged_pt = b''
    for op, ticker, num in todays_trades:
        if op == 'B': op = 'S'
        else: op = 'B'
        munged_pt += format_trade(op, ticker, num)
    todays_ct = ctx.encrypt(old_pt)
    ctx = AES.new(k, AES.MODE_CTR, nonce=b'11111111')
    expected = ctx.encrypt(munged_pt)

    return k, {'todays_ct' : todays_ct.hex()}, expected.hex()


def create_problem_4_instance():
    k = secrets.token_bytes(16)
    nonces = [b'00000000', b'11111111']
    enums = []
    anums = []
    ilist = []
    olist = []
    
    for i in range(2):
      ticker = ticker_symbols[secrets.randbelow(len(ticker_symbols))]
      op  = trade_ops[secrets.randbits(1)]
      num = secrets.randbelow(1000)
      opt = format_trade(op, ticker, num)
      enums.append(num)
      anums.append(num + 10000)
      if op == 'B':
          other_op = 'S'
      else:
          other_op = 'B'
      mpt = format_trade(other_op, ticker, num + 10000)
      ctx = AES.new(k, AES.MODE_CTR, nonce=nonces[i])
      ilist.append(ctx.encrypt(opt).hex())
      ctx = AES.new(k, AES.MODE_CTR, nonce=nonces[i])
      olist.append(ctx.encrypt(mpt).hex())

    in1 = { 'trade_list' : ilist, 'expected_num' : enums,
            'actual_num' : anums }
    return k, in1, olist
        
def check_one_p1(sent_ct, attack_ct, possibles, to_replace, best):
    sent_ct = bytes.fromhex(sent_ct)
    attack_ct = bytes.fromhex(attack_ct)
    
    used_other_than_the_best = False
    
    if len(sent_ct) != len(attack_ct):
        return 0
    while sent_ct:
        s = sent_ct[:16]
        a = attack_ct[:16]
        sent_ct = sent_ct[16:]
        attack_ct = attack_ct[16:]
        if s not in to_replace:
            if a != s:
                return 0
            continue
        if a == best:
            continue
        if a not in possibles:
            return 0
        used_other_than_the_best = True

    if used_other_than_the_best:
        return -1
    
    return 1
                

def grade_problem_1(jblob, key, invals, possibles, best, to_replace):
    if not "problem 1" in jblob:
        err("not provided.")
        return 0

    res   = jblob["problem 1"]
    score = 0
    possibles  = set(possibles.values())
    to_replace = set(to_replace.values())
    new_trades = invals["new_trades"]

    used_other_than_the_best = False

    for i in range(len(new_trades)):
        if i > len(res):
            err("Missing result", i + 1)
        else:
            sent_ct   = new_trades[i]
            attack_ct = res[i]
            n = check_one_p1(sent_ct, attack_ct, possibles, to_replace, best)
            if n:
                err("    Part %d: pass." % (i + 1))
                score += 1
                if n == -1:
                    used_other_than_the_best = True
            else:
                err("    Part %d: fail." % (i + 1))

    if score == 2:
        if not used_other_than_the_best:
            return 3
        err("    -1 point: Didn't always use the highest trade value.")
        return 2
        
    return score

def grade_problem_2(jblob, expected):
    err("Problem 2:  ", end='')
    if not "problem 2" in jblob:
        err("not provided.")
        return 0

    if (expected.upper() == jblob["problem 2"].upper()):
        err("pass.")
        return 3

    err("fail.")
    return 0

def grade_problem_3(jblob, expected):
    err("Problem 3:  ", end='')
    if not "problem 3" in jblob:
        err("not provided.")
        return 0
    
    if (expected.upper() == jblob["problem 3"].upper()):
        err("pass.")
        return 2

    err("fail.")
    return 0

def grade_problem_4(jblob, expected):
    err("Problem 4: ", end='')
    if not "problem 4" in jblob:
        err("not provided.")
        return 0

    score = 0
    
    res = jblob["problem 4"]

    err()
    
    for i in range(len(expected)):
        if (i > len(res)):
            err("Missing result", i + 1)
        else:
            if res[i].lower().strip() == expected[i].lower().strip():
                err("    Part %d: pass." % (i + 1))
                score += 1
            else:
                err("    res[i] != expected[i]:", res[i], expected[i])
                
    return score

def err(s='', end='\n'):
    print(s, file=sys.stderr, end=end)

def exit_showing_errors():

    try:
        with open('errors.out') as f:
            err()
            err(f.read())
    finally:
        sys.exit(0)

def grade():
    p1_key, p1_invals, p1_poss, best, p1_repl = create_problem_1_instance()
    p2_key, p2_invals, p2_expected = create_problem_2_instance()
    p3_key, p3_invals, p3_expected = create_problem_3_instance()
    p4_key, p4_invals, p4_expected = create_problem_4_instance()
    
    jblob = json.dumps({
        "problem 1" : p1_invals,
        "problem 2" : p2_invals,
        "problem 3" : p3_invals,
        "problem 4" : p4_invals })

    with open('inputs.json', 'w') as f:
      f.write(jblob)

    os.system("./ps2 < inputs.json > outputs.json 2> errors.out")


    try:
        with open('outputs.json', 'r') as f:
           res_raw = f.read()
    except:
        err("Was not able to get your program to output json.")
        exit_showing_errors()

    try:
        jblob = json.loads(res_raw)
    except:
        err("Output of your program wasn't parsable as JSON.")
        exit_showing_errors()

    scores = []
    
    scores.append(grade_problem_1(jblob, p1_key, p1_invals, p1_poss, best, p1_repl))
    scores.append(grade_problem_2(jblob, p2_expected))
    scores.append(grade_problem_3(jblob, p3_expected))
    scores.append(grade_problem_4(jblob, p4_expected))

    return [x * 10 for x in scores]


def output_json(max_scores, scores):
    problem_objects = []
    output = { "stdout_visibility" : "visible",
               "tests" : problem_objects,
               "output" : "Thanks for submitting. Remember that you can re-submit as many times as you like, as long as the assignment is open!"
               }

    for i in range(len(scores)):
        problem_objects.append({
            "name" : "problem %d" % (i + 1),
            "max_score" : max_scores[i],
            "score" : scores[i]
        })

    json.dump(output, sys.stdout, indent = "  ")


max_scores = [30, 30, 20, 20]

scores = grade()

output_json(max_scores, scores)
    

