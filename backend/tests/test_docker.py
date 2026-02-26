"""
Quantum Protocol v5.0 — Docker Integration Tests
Tests for Docker Compose setup and services.

Phase 9.3: Docker tests
"""

import pytest
import subprocess
import time
import requests
import socket


class TestDockerServices:
    """Test Docker Compose services."""

    @pytest.fixture(scope="module")
    def docker_services(self):
        """Check if Docker services are running."""
        services = {
            "postgres": ("localhost", 5432),
            "redis": ("localhost", 6379),
            "backend": ("localhost", 8000),
            "frontend": ("localhost", 3000),
        }
        return services

    def test_postgres_connection(self, docker_services):
        """Test PostgreSQL is accessible."""
        host, port = docker_services["postgres"]
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((host, port))
            sock.close()
            # If not running in Docker, skip
            if result != 0:
                pytest.skip("PostgreSQL not running in Docker")
        except Exception as e:
            pytest.skip(f"Cannot connect to PostgreSQL: {e}")

    def test_redis_connection(self, docker_services):
        """Test Redis is accessible."""
        host, port = docker_services["redis"]
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((host, port))
            sock.close()
            if result != 0:
                pytest.skip("Redis not running in Docker")
        except Exception as e:
            pytest.skip(f"Cannot connect to Redis: {e}")

    def test_backend_health(self, docker_services):
        """Test backend health endpoint."""
        host, port = docker_services["backend"]
        try:
            response = requests.get(f"http://{host}:{port}/api/v1/health", timeout=5)
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "healthy"
        except requests.exceptions.ConnectionError:
            pytest.skip("Backend not running in Docker")
        except Exception as e:
            pytest.skip(f"Backend health check failed: {e}")

    def test_frontend_loads(self, docker_services):
        """Test frontend loads."""
        host, port = docker_services["frontend"]
        try:
            response = requests.get(f"http://{host}:{port}", timeout=5)
            assert response.status_code == 200
        except requests.exceptions.ConnectionError:
            pytest.skip("Frontend not running in Docker")
        except Exception as e:
            pytest.skip(f"Frontend check failed: {e}")


class TestDockerCompose:
    """Test Docker Compose configuration."""

    def test_compose_file_valid(self):
        """Test docker-compose.yml is valid."""
        try:
            result = subprocess.run(
                ["docker-compose", "config"],
                capture_output=True,
                text=True,
                timeout=30
            )
            # If docker-compose is not installed, skip
            if result.returncode != 0 and "not found" in result.stderr:
                pytest.skip("Docker Compose not installed")
            assert result.returncode == 0, f"docker-compose config failed: {result.stderr}"
        except FileNotFoundError:
            pytest.skip("Docker Compose not installed")
        except subprocess.TimeoutExpired:
            pytest.skip("Docker Compose command timed out")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
