import os

class SecurityBehaviorChecker:
    def suspicious_calls(self):
        suspicious = []
        syscalls = ["os.system", "eval", "exec"]
        try:
            # quét mã nguồn hiện tại để tìm các lệnh nguy hiểm
            with open(__file__, 'r') as f:
                content = f.read()
                for call in syscalls:
                    if call in content:
                        suspicious.append(call)
        except Exception:
            pass
        return suspicious
