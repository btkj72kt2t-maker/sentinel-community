import unittest

from sentinel.policy import execution_decision


class Engagement(dict):
    pass


class PolicyTests(unittest.TestCase):
    def test_kill_switch_overrides_approval(self):
        eng = Engagement(kill_switch=1, active_enabled=1, lab_mode=1)
        self.assertFalse(execution_decision(eng, active=True, approved=True).allowed)

    def test_active_requires_two_gates(self):
        eng = Engagement(kill_switch=0, active_enabled=1, lab_mode=0)
        self.assertFalse(execution_decision(eng, active=True, approved=False).allowed)
        self.assertTrue(execution_decision(eng, active=True, approved=True).allowed)

    def test_lab_operation_requires_lab_mode(self):
        eng = Engagement(kill_switch=0, active_enabled=1, lab_mode=0)
        self.assertFalse(execution_decision(eng, active=False, lab_only=True).allowed)


if __name__ == "__main__":
    unittest.main()
