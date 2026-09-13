<h1 align="center">TWRP for HONOR 50 SE</h1>

<p align="center">
  荣耀 50 SE · JLH-AN00 · TWRP Recovery 适配
</p>

<p align="center">
  <img src="https://img.shields.io/badge/TWRP-Unofficial-007EA7?style=flat-square" alt="非官方 TWRP 适配">
  <img src="https://img.shields.io/badge/Device-JLH--AN00-475569?style=flat-square" alt="适用型号 JLH-AN00">
  <img src="https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square" alt="构建工具 Python 3.12">
  <img src="https://img.shields.io/badge/Tested--Base-Magic%20UI%206.1.0.120-8B5CF6?style=flat-square" alt="实测基线 Magic UI 6.1.0.120">
</p>



为荣耀 50 SE 提供中文界面、触摸支持、已有加密数据读取、滑动清除、userspace Fastboot。

## 功能状态

| 功能 | 状态 | 说明 |
| --- | --- | --- |
| 中文界面与触摸 | ✅ 已验证 | 实机主菜单和触摸操作正常 |
| 加密数据读取 | ✅ 已验证 | 已验证测试机 DE/CE 读取；v21 启动及重启后的解密检查通过 |
| 非 Data 分区备份 | ✅ 已验证 | 103 项原生全选备份，包含 A/B、Super 和两个独立 UFS 区域 |
| 备份文件校验 | ✅ 已验证 | 大小、SHA-256、全部 `.sha2` 及 Recovery 重启后的复查通过 |
| userspace Fastboot | ✅ 已验证 | 进入 fastbootd、查询设备信息、返回 Recovery 通过 |

以下范围仍缺少独立验证： MTP 文件传输。


## 支持设备

| 项目 | 已验证配置 |
| --- | --- |
| 设备 | 荣耀 50 SE / HONOR 50 SE |
| 型号与产品标识 | `JLH-AN00` / `HNJLH` |
| 镜像对应分区 | `recovery_ramdisk` |
| 实测固件基线 | Magic UI 6.1.0.120(C00)，原厂 boot / vendor_boot 保留未动 |
| 安装条件 | 已具备运行自定义 Recovery 的条件（解锁BL） |

镜像没有原厂签名。现有验证不能直接覆盖原厂锁定设备或其他解锁方式。

<a id="download"></a>

## 下载与安装

从本仓库的 **Releases** 获取镜像及 `SHA256SUMS.txt`。

| 文件 | 用途 |
| --- | --- |
| `recovery_ramdisk.img` | Recovery ramdisk 镜像，32 MiB |
| `SHA256SUMS.txt` | Release 文件的 SHA-256 校验清单 |

<details>
<summary> 镜像完整 SHA-256 </summary>

```text
dd8973e46a7a731f0267623efeb764a2f279f2783d8c25dbee9ed3c74bac5df0
```

文件大小：33,554,432 字节。

</details>

### 校验完整性

下载后先核对哈希，应与 `SHA256SUMS.txt` 一致：

```bat
certutil -hashfile recovery_ramdisk.img SHA256
```

```bash
sha256sum recovery_ramdisk.img
```

### 刷入

> 仅适用于已解锁 BL 的设备。刷写第三方 Recovery 有变砖与数据丢失风险，建议先在 TWRP 中完成全盘备份后再继续。

准备：PC 安装 [Android platform-tools](https://developer.android.com/tools/releases/platform-tools)（含 adb / fastboot），手机开启 USB 调试并连接。

1. 重启到 bootloader：

   ```bash
   adb reboot bootloader
   ```

   （关机状态下也可长按 **音量下 + 连接数据线** 进入 fastboot。）

2. 在镜像所在目录刷入（文件名即分区名，A/B 双槽建议都写）：

   ```bash
   fastboot flash recovery_ramdisk_a recovery_ramdisk.img
   fastboot flash recovery_ramdisk_b recovery_ramdisk.img
   ```

   只写当前活动槽时，也可用 `fastboot flash recovery_ramdisk recovery_ramdisk.img`。

3. 进入 TWRP：

   ```bash
   adb reboot recovery
   ```

   （重启进入系统后执行；关机状态下长按 **电源键 + 音量上键** 的常规组合键通常也可进入。）

4. 首次进入 TWRP 后，建议先做一次全选备份再进行其他操作。

### 回退与救援

- **回原厂 Recovery**：刷回官方固件中的原厂 `recovery_ramdisk` 镜像即可。本镜像不写 vbmeta 与其他任何分区，原厂系统不受影响。
- **进入 fastboot**：关机长按 **音量下 + 连接数据线**，或 `adb reboot bootloader`。

## 已知问题

| 问题 | 现状 | 替代方案 |
| --- | --- | --- |
| MTP 文件传输 | 未独立验证 | 用 `adb push` / `adb pull` 与电脑互传文件；刷整包走 **高级 → ADB Sideload**，PC 端执行 `adb sideload <zip>` |



## 致谢与许可

感谢 [TeamWin / TWRP](https://github.com/TeamWin/android_bootable_recovery)、[lopestom](https://github.com/lopestom/twrp_device_xiaomi_pissarro) 的 pissarro 设备树、[MengWanYu](https://github.com/MengWanYu/Honor50SE_DeviceTree_Twrp) 的早期参考与资源包，以及 [AOSP](https://source.android.com/)。

各组件保留其原有许可；本项目新增文件以 [GPL-3.0](LICENSE) 发布。
