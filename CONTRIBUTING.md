# 🤝 Contributing to recon.sh

We welcome contributions from the security community! By participating in this project, you agree to abide by our Code of Conduct and LICENSE.

## How to Contribute

1.  **Fork** the repository on GitHub.
2.  **Clone** your fork locally.
3.  **Create a new branch** for your feature or fix:
    ```bash
    git checkout -b feature/your-awesome-feature
    ```
4.  **Make your changes** to `recon.sh`. Please ensure your code follows POSIX compliance and includes comments for complex sections.
5.  **Test** your changes locally to ensure no existing functionality is broken.
6.  **Commit** your changes with a descriptive message:
    ```bash
    git commit -m "feat: Add new module for WAF detection"
    ```
7.  **Push** your branch to your fork.
8.  **Open a Pull Request** against the `main` branch of the original repository.

## Standards

* All additions must be compatible with the core Bash script architecture.
* New modules should include dependency checks (`command -v tool &>/dev/null`) and handle concurrency correctly.
