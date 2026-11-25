"""Lab proof reports: metrics, charts, mini-report for optimization upgrades."""

__all__ = ["generate_lab_proof_report"]


def __getattr__(name: str):
    if name == "generate_lab_proof_report":
        from .generate_report import generate_lab_proof_report

        return generate_lab_proof_report
    raise AttributeError(name)
