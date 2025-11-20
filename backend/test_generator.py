from generator import generate_ssh_bruteforce_log

def test_10_lines():
    log = generate_ssh_bruteforce_log(attempts=10)
    lines = log.split('\n')
    assert len(lines) == 10
    print("✅ Test 10 lines: PASSED")

def test_100_lines():
    log = generate_ssh_bruteforce_log(attempts=100)
    lines = log.split('\n')
    assert len(lines) == 100
    print("✅ Test 100 lines: PASSED")

if __name__ == "__main__":
    test_10_lines()
    test_100_lines()
    print("\n🎉 All tests PASSED!")
