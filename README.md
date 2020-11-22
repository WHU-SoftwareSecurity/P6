<h1 align="center">Welcome to P6 👋</h1>
<p>
  <img alt="Version" src="https://img.shields.io/badge/version-0.1-blue.svg?cacheSeconds=2592000" />
  <a href="#" target="_blank">
    <img alt="License: MIT" src="https://img.shields.io/badge/License-MIT-yellow.svg" />
  </a>
</p>


> shellcode的注入和清除实验

### 🏠 [Homepage](https://github.com/WHU-SoftwareSecurity/P6)

## Introduction

该仓库用作实现2018级武汉大学国家网络安全学院软件安全[P6作业](docs/P6-shellcode文件注入（编程作业）说明.pdf)

已经实现以及未实现的功能：

> :white_check_mark: 32/64位PE程序头信息解析和获取
>
> :white_check_mark: 32/64位PE程序导入/导出函数信息获取
>
> :white_check_mark: 32/64位PE程序查询、关闭、打开ASLR
>
> :white_check_mark: 32/64位PE程序代码空洞信息获取
>
> :white_check_mark: 32位PE程序文件注入
>
> - 代码空洞
> - 新增节
>
> :white_check_mark: 32位PE程序注入清除
>
> :x: 64位PE程序文件注入
>
> :x: 64位PE程序注入清除

## Usage

**!!!测试时请务必使用副本，该程序会直接对目标程序进行修改**

使用样例可参考文件[test.cpp](PEAnalysis/test.cpp)

#### 关键API说明

- 初始化`PEHelper`

  ```c++
  string pe_path("./hello_world.exe");
  
  PEHelper pe_helper;
  pe_helper.LoadPE(pe_path);
  ```

- 输出PE信息

  ```c++
  pe_helper.DisplayInfo();
  ```

- 查看ASLR状态

  ```c++
  // 开启返回 true, 关闭返回 false
  bool is_open = pe_helper.HasASLR();
  ```

- 开启、关闭ASLR

  ```c++
  pe_helper.CloseASLR();
  pe_helper.OpenASLR();
  ```

- 搜索代码空洞

  ```c++
  vector<CodeCave> code_cave = pe_helper.SearchCodeCave();
  // CodeCave 定义如下
  // 代码空洞结构体，包括节名、第几个节、代码空洞 FOA，代码空洞 RVA 和代码空洞大小
  typedef struct _CodeCave {
  	BYTE name[8];
  	BYTE section_number;
  	ULONGLONG start_foa;
  	ULONGLONG start_rva;
  	DWORD size;
  } CodeCave;
  ```

- 初始化`InfectHelper`

  ```c++
  InfectHelper infect_helper(pe_path);
  ```

- 判断目标文件是否已经被感染

  ```c++
  bool is_infected = infect_helper.IsInfected();
  ```

- 新增节注入

  ```c++
  string new_section_name(".qiufeng");
  // 如果已经被注入或者注入失败, 返回 false
  bool if_success = infect_helper.InfectByAddSection(new_section_name);
  ```

- 自定义shellcode新增节注入

  ```c++
  // 这里 shellcode 的格式必须前 4 个字节存储 OEP, 最后的指令类似于 jmp OEP
  string shellcode(...);
  
  bool if_success = infect_helper.InfectByAddSection(new_section_name, shellcode);
  ```

- 代码空洞注入

  ```c++
  // 注入代码到节空洞起始位置的偏移
  DWORD offset = 0x20;
  
  bool if_success = infect_helper.InfectByCodeCave(offset);
  ```

- 自定义代码空洞注入类似于新增节注入

- 文件注入清除

  ```c++
  // 如果没有注入, 返回 false
  bool if_success = infect_helper.RemoveVirus();
  ```

## 遇到的坑

- 对于某些PE文件(e.g. user32.dll)，其末尾有`Certification Table`不在任何一个节内，在不创建新文件的情况下难以进行新增节注入。除此之外，有些PE文件还有其他不知名的部分(pyinstaller 生成的文件)
- PE32和PE64的可选文件头中某些属性的长度不一样(e.g. ImageBase)，给注入造成了困难
- visual studio在x64模式下无法使用内联汇编`__asm`
- 进行字符串比较的汇编代码只能每次比较4个字节

## Author

👤 **Group 8**

* Github: [@WHU-SoftwareSecurity ](https://github.com/WHU-SoftwareSecurity )

## Show your support

Give a ⭐️ if this project helped you!

***
_This README was generated with ❤️ by [readme-md-generator](https://github.com/kefranabg/readme-md-generator)_