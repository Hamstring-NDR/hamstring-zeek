
<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/stefanDeveloper/heiDGAF">
    <img src="https://raw.githubusercontent.com/stefanDeveloper/heiDGAF/main/assets/heidgaf_logo_normal.png?raw=true" alt="Logo">
  </a>

<h3 align="center">Hamstring - Zeek</h3>

  <p align="center">
    Zeek based module to ingest data in the main Hamstring application based on Apache Kafka queues.
    <br />
    <br>
    <a href="https://github.com/stefanDeveloper/heiDGAF/issues/new?labels=bug&template=bug-report---.md">Report Bug</a>
    ·
    <a href="https://github.com/stefanDeveloper/heiDGAF/issues/new?labels=enhancement&template=feature-request---.md">Request Feature</a>
  </p>
</div>
<br>
<table>
<tr>
  <td><b>Continuous Integration</b></td>
  <td>
    <a href="https://github.com/Hamstring-NDR/hamstring-zeek/actions/workflows/build_test_linux.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/Hamstring-NDR/hamstring-zeek/build_test_linux.yml?branch=main&logo=linux&style=for-the-badge&label=linux" alt="Linux WorkFlows" />
    </a>
    <a href="https://github.com/Hamstring-NDR/hamstring-zeek/actions/workflows/build_test_macos.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/Hamstring-NDR/hamstring-zeek/build_test_macos.yml?branch=main&logo=apple&style=for-the-badge&label=macos" alt="MacOS WorkFlows" />
    </a>
    <a href="https://github.com/Hamstring-NDR/hamstring-zeek/actions/workflows/build_test_windows.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/Hamstring-NDR/hamstring-zeek/build_test_windows.yml?branch=main&logo=windows&style=for-the-badge&label=windows" alt="Windows WorkFlows" />
    </a>
  </td>
</tr>
</table>

<br>

## Getting Started

#### Run hamstring's Zeek module using Docker Compose:

```sh
HOST_IP=127.0.0.1 docker compose -f docker/docker-compose.yml --profile prod up
```

Please note that in order for the module to work, you need to have an instance of Hamstring running. To do so, please refer to the [official hamstring repository](https://github.com/Hamstring-NDR/hamstring).
