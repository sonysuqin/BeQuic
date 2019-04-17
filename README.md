@[TOC](FFmpeg支持QUIC)
# 1 背景
QUIC也就是HTTP3，是Google为了解决HTTP2的一些问题提出的基于UDP的传输方案。HTTP2由于队头堵塞、握手延迟等缺陷并没有普及，相反由于QUIC的优势，Youtube已经全面使用了QUIC。现在去看Youtube的视频，对一个HTTP1/2的请求，Youtube返回的HTTP1/2响应中会携带一个支持QUIC协议的头，Chrome缓存该头中携带的地址，下次对该地址的请求会以QUIC协议发出，之后跟该服务的数据交互将以基于UDP的QUIC协议进行。

QUIC的主要优点是减少握手延迟(号称0RTT)、出色的流控(BBR、CUBIC)、多路复用等，已经成为事实上的下一代HTTP标准。但是目前该标准在实现上有两个版本，一个是IETF的版本，一个是Google自己的版本，这两者目前并不互通。

本文介绍了基于Google的QUIC协议封装的bequic库，并集成到FFmpeg中，让FFmpeg可以通过QUIC协议播放视频。
# 2 代码地址
bequic：
[https://github.com/sonysuqin/BeQuic](https://github.com/sonysuqin/BeQuic)
FFmpeg：
[https://github.com/sonysuqin/FFmpeg](https://github.com/sonysuqin/FFmpeg)
# 3 方案
bequic库封装了Google Chromium Quiche库，对外提供C的接口，因此需要完整下载chromium项目代码用于编译。对FFmpeg，需要增加一个quic协议，主要用于调用bequic库。
## 3.1 bequic  -  Google Quiche封装
增加一个Chromium的动态库工程，修改chromium/src/net/BUILD.gn（在[BeQuic代码](https://github.com/sonysuqin/BeQuic)的patch目录下）

```
+  shared_library("libbequic") {
+    sources = [
+      "tools/quic/basic_streambuf.hpp",
+      "tools/quic/basic_streambuf_fwd.hpp",
+      "tools/quic/be_quic_define.h",
+      "tools/quic/be_quic.h",
+      "tools/quic/be_quic.cc",
+      "tools/quic/be_quic_client.h",
+      "tools/quic/be_quic_client.cc",
+      "tools/quic/be_quic_client_manager.h",
+      "tools/quic/be_quic_client_manager.cc",
+      "tools/quic/be_quic_fake_proof_verifier.h",
+      "tools/quic/be_quic_fake_proof_verifier.cc",
+      "tools/quic/be_quic_spdy_client.h",
+      "tools/quic/be_quic_spdy_client.cc",
+      "tools/quic/be_quic_spdy_client_session.h",
+      "tools/quic/be_quic_spdy_client_session.cc",
+      "tools/quic/be_quic_spdy_client_stream.h",
+      "tools/quic/be_quic_spdy_client_stream.cc",
+      "tools/quic/buffer.hpp",
+      "tools/quic/streambuf.hpp",
+    ]
+    deps = [
+      ":net",
+      ":simple_quic_tools",
+      "//base",
+      "//build/win:default_exe_manifest",
+      "//url",
+    ]
+    defines = [ "BE_QUIC_EXPORTS", "BE_QUIC_SHARED_LIBRARY" ]
+  }

```
添加的文件就是bequic库的实现文件(在[BeQuic代码](https://github.com/sonysuqin/BeQuic)的src/chromium目录下)，主要实现了以下接口：
* be_quic_open：建立一个QUIC会话，并打开一个流；
* be_quic_close：关闭QUIC会话，关闭所有流；
* be_quic_read：读QUIC会话当前流的数据；
* be_quic_seek：Seek到文件指定位置，可能会打开一个新的流。

> 对seek来说，传统HTTP使用的是带Range头的请求，而Youtube目前并没有使用这个头，而是在URL中携带range参数：http://xx.com/xx.html?……&range=1024-2048&……

> 对BoringSSL与OpenSSL可能的符号冲突，参考这个链接：[https://boringssl.googlesource.com/boringssl/+/HEAD/INCORPORATING.md](https://boringssl.googlesource.com/boringssl/+/HEAD/INCORPORATING.md)，需要编译成动态库并隐藏符号。
## 3.2 FFmpeg  -  增加quic协议
这里在FFmpeg4.1分支上创建了一个4.1.quic分支，可以在[https://github.com/sonysuqin/FFmpeg](https://github.com/sonysuqin/FFmpeg)上查看基于该分支的修改，主要是修改了configure、Makefile，并在libavformat下增加了bequic.c，用于调用bequic库。

>在Windows下，FFMpeg使用MSYS2+MINGW32+GCC编译，chromium使用clang-cl编译，两者的符号不一致，需要使用dlltool等工具对chromium项目编译出的bequic库进行处理，得到GCC可以链接的库。
# 4 编译
## 4.1 Windows
### 4.1.1 编译环境
| 软件| 版本|
|:--|:--|
| Windows | 10 |
| MSYS2 + MINGW|  最新版，还要安装GCC等工具 |
| Chromium |  最新版，版本号4c428bdc69a2c16fdb0c5576e4098373bd6cc4e3 |
| FFMpeg |  4.1 |
### 4.1.2 目录结构
确保目录结构如下：
```
quic
|-- BeQuic
|-- chromium
`-- FFmpeg
```
### 4.1.3 编译bequic
#### 4.1.3.1 下载bequic源码
在quic目录下，执行：
```
git clone https://github.com/sonysuqin/BeQuic.git
```
#### 4.1.3.2 下载chromium源码
在quic目录下，按照chromium的[官方编译文档](https://chromium.googlesource.com/chromium/src/+/master/docs/windows_build_instructions.md)，下载chromium代码(需要一个比较好的VPN)。
#### 4.1.3.3 打bequic补丁
使用MSYS2进入BeQuic/patch目录下，执行
```
./patch.sh
```
该脚本的作用：
* 把BeQuic/patch/BUILD.gn拷贝到chromium/src/net目录下；
* 把BeQuic/src/chromium下的文件拷贝到chromium/src/net/tools/quic目录下；

> 补丁并不修改chromium的源代码。

#### 4.1.3.4 生成工程
在chromium/src下执行：
```
gn gen out/Debug--args="is_debug=true is_component_build=false target_cpu=\"x86\""
```
这里可以决定是产生Debug版还是Release版。
#### 4.1.3.5 编译 bequic库
在chromium/src下执行：
```
ninja -C out\Debug libbequic
```
#### 4.1.3.6 编译quic_server  - 用于测试
在chromium/src下执行：
```
ninja -C out\Debug quic_server
```
### 4.1.4 编译FFmpeg
#### 4.1.4.1 安装依赖
安装GCC、SDL2等FFmpeg通常需要依赖的工具，主要参考了以下这些网页：
[《msys2和SDL2环境搭建》](https://dongqiceo.github.io/the-post-9982/)
[《windows下编译FFMPEG篇》](https://blog.csdn.net/listener51/article/details/81605472)
[《Windows10平台编译ffmpeg 4.0.2，生成ffplay》](https://www.cnblogs.com/harlanc/p/9569960.html)
#### 4.1.4.2 下载支持bequic的FFmpeg源码
在quic目录下，执行

```
git clone https://github.com/sonysuqin/FFmpeg.git
```
#### 4.1.4.3 处理bequic库的符号
将BeQuic/script/gen_a.sh拷贝到chromium/src/out/Debug目录下，执行：

```
./gen_a.sh
```

该脚本很简单：

```
gendef libbequic.dll
dlltool --kill-at -d libbequic.def --dllname libbequic.dll -l libbequic.a
```
使用gendef产生libbequic.dll的def文件，然后用dlltool产生GCC可以链接的libbequic.a。

#### 4.1.4.4 configure
在FFmpeg目录下，执行：
```
mkdir build
cd build
../configure --disable-static --enable-shared --enable-gpl --enable-version3 --enable-sdl --enable-debug=3 --disable-optimizations --disable-mmx --disable-stripping --arch=x86 --enable-libbequic --extra-cflags=-I/d/work/google/chromium/src/net/tools/quic --extra-ldflags=-L/d/work/google/chromium/src/out/Debug --extra-libs=-lbequic
```
注意修改--extra-cflags、--extra-ldflags为实际的bequic库的头文件、库文件的路径。

#### 4.1.4.5 编译
在FFmpeg/build目录下，执行：

```
make && make install
```
注意把chromium/src/out/Debug/libbequic.dll拷贝到ffplay运行目录。
## 4.2 Android
### 4.2.1 编译环境
| 软件| 版本|
|:--|:--|
| Ubuntu | 16.04 |
| NDK |  r17c |
| Chromium |  最新版，版本号e57cf4b40708a719439ad3895279b7de1feb62a8|
| FFMpeg |  4.1.quic |
### 4.2.2 目录结构
确保目录结构如下：
quic
|-- BeQuic
|-- chromium
`-- FFmpeg
### 4.2.3 编译bequic
#### 4.2.3.1 下载bequic源码
在quic目录下，执行：
```
git clone https://github.com/sonysuqin/BeQuic.git
```
#### 4.2.3.2 下载chromium源码
在quic目录下，按照chromium的[官方编译文档](https://chromium.googlesource.com/chromium/src/+/master/docs/android_build_instructions.md)，下载chromium代码(需要一个比较好的VPN)。
#### 4.2.3.3 打bequic补丁
进入BeQuic/patch目录下，执行
```
mv BUILD.gn BUILD.gn.bak
mv BUILD.gn.Android BUILD.gn
./patch.sh
mv BUILD.gn BUILD.gn.Android
mv BUILD.gn.bak BUILD.gn
```
目的：
* 将BeQuic/patch/BUILD.gn.Android覆盖chromium/src/net目录下的BUILD.gn文件；
* 把BeQuic/src/chromium下的文件拷贝到chromium/src/net/tools/quic目录下；

> 补丁并不修改chromium的源代码。

#### 4.2.3.4 生成工程
在chromium/src下执行：
```
gn gen out/Release --args="is_debug=false is_component_build=false target_os=\"android\"  target_cpu=\"arm\""
```
这里可以决定是产生Debug版还是Release版。
#### 4.2.3.5 编译 bequic库
在chromium/src下执行：

```
ninja -C out/Release libbequic
```
### 4.2.4 编译FFmpeg
#### 4.2.4.1 下载支持bequic的FFmpeg源码
在quic目录下，执行

```
git clone https://github.com/sonysuqin/FFmpeg.git
```

#### 4.2.4.2 编译
在FFmpeg/build目录下，执行：

```
./build_android.sh
```
在编译脚本中，需要指定NDK工具链的路径，libbequic库的头文件、库路径等(如果按照上述目录结构就不用修改)，脚本会将编译产生的所有输出放在当前目录的android目录下。
#### 4.2.4.3 Androd端简单测试
用Android Studio(3.4)打开BeQuic/test/android目录下的TestFFmpegQuic工程，将4.2.4.2节编译产生的所有.so库拷贝到BeQuic/test/android/TestFFmpegQuic/FFmpegQuic/src/main/jni/FFmpeg/lib/armeabi-v7a目录下，连接Android手机，编译、运行。

### 4.3 TBD
Linux(已完工)、iOS、Mac OSX.

# 5 测试
在Google的[Playing With QUIC](https://www.chromium.org/quic/playing-with-quic)页面有测试的详细介绍，这里只介绍Windows端的测试步骤，Linux、Mac OSX的步骤类似，都是用ffplay播放，Android、iOS平台没有编译ffplay，只是写了简单的测试程序调用FFmpeg的API，通过QUIC协议获取到数据即可。
## 5.1 准备测试文件
### 5.1.1 准备文件源
另外准备一个HTTP服务，例如nginx，假设其地址为192.168.116.133，在其html根目录放置一个文件：1.mp4；
### 5.1.2 修改hosts
在本机(Windows10)修改hosts，域名指向nginx的地址；
```
192.168.116.133 www.example.org
```
### 5.1.3 下载文件源并保留HTTP头
在MSYS2下面，执行：
```
mkdir /tmp/quic-data
cd /tmp/quic-data
wget -p --save-headers http://www.example.org/1.mp4
```
### 5.1.4 修改HTTP头
使用编辑器(例如vi)修改/tmp/quic-data/www.example.org/1.mp4，修改其HTTP头：
* 如果有"Transfer-Encoding: chunked"头就删除；
* 如果有"Alternate-Protocol"头就删除；
* 增加"X-Original-Url: https://www.example.org/"头。

### 5.1.5 修改hosts 
在本机(Windows10)修改hosts，域名指向本地；
```
127.0.0.1 www.example.org
```
## 5.2 生成并安装证书
主要用于quic-server。
### 5.2.1 生成证书
进入chromium/src/net/tools/quic/certs目录，执行：

```
./generate-certs.sh
```
out目录下就是产生的证书。
### 5.2.2 安装证书
进入chromium/src/net/tools/quic/certs/out目录，执行：

```
certutil -addstore -f "ROOT" 2048-sha256-root.pem
```
## 5.3 启动quic-server
在chromium/src目录下，执行：
```
./out/Debug/quic_server   --quic_response_cache_dir=/tmp/quic-data/www.example.org   --certificate_file=net/tools/quic/certs/out/leaf_cert.pem   --key_file=net/tools/quic/certs/out/leaf_cert.pkcs8
```
## 5.4 启动ffplay
在FFmpeg/build目录下，执行：

```
./ffplay quic://www.example.org:6121 -timeout 1000 -verify_certificate 1
```
> 如果设置-verify_certificate 0，则可以省略证书生成和安装环节。

![在这里插入图片描述](https://img-blog.csdnimg.cn/20190404171904781.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3NvbnlzdXFpbg==,size_16,color_FFFFFF,t_70)
