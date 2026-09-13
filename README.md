<h1 align="center">TWRP for HONOR 50 SE</h1>

<p align="center">
  荣耀 50 SE · JLH-AN00 ·TWRP Recovery 适配
</p>

<p align="center">
  <img src="https://img.shields.io/badge/TWRP-Unofficial-007EA7?style=flat-square" alt="非官方 TWRP 适配">
  <img src="https://img.shields.io/badge/Device-JLH--AN00-475569?style=flat-square" alt="适用型号 JLH-AN00">
  <img src="https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square" alt="构建工具 Python 3.12">
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
<summary> 镜像完整 SHA-256</summary>

```text
dd8973e46a7a731f0267623efeb764a2f279f2783d8c25dbee9ed3c74bac5df0
```

文件大小：33,554,432 字节。

## 致谢与许可

感谢 [TeamWin / TWRP](https://github.com/TeamWin/android_bootable_recovery)、[lopestom](https://github.com/lopestom/twrp_device_xiaomi_pissarro) 及 [AOSP](https://source.android.com/)。

各组件保留其原有许可；本项目新增文件尚未选定统一开放许可证。历史供体的准确对应源码版本仍待确认。分发与使用条件见。

