# 修复说明：显式版本的本地目录 replace 导致漏洞静默漏报

## 一、现象

工程通过 `go.mod` 的 replace 把某个依赖指到本地目录做联调，且 replace
显式带了版本号：

```
require golang.org/x/text v0.3.0
replace golang.org/x/text v0.3.0 => ../localmods/x-text
```

安全情报确认该依赖版本里有问题的符号在生产代码中真实可达，但扫描器对整个
工程只输出 `No vulnerabilities found`，退出码 0，调整扫描范围也不变。把
replace 去掉、换回仓库版本后，扫描立刻报出漏洞；再换回本地目录又归于静默。

## 二、根因：显式版本为什么"不算数"，扫描器在版本匹配链路上丢了什么

先看 go 命令对这种 replace 实际产出的模块结构（`go list -m -json`）：

```json
{
  "Path": "golang.org/x/text",
  "Version": "v0.3.0",
  "Replace": {
    "Path": "../localmods/x-text",
    "Dir":  ".../localmods/x-text",
    "GoVersion": "1.20"
  }
}
```

关键点：**replace 行里写的 `v0.3.0` 不会出现在 `Replace` 节点上**。
本地目录替换的 `Replace.Version` 恒为空——本地目录没有模块版本；那个显式
版本只保留在外层模块的 `Version` 字段。`Replace.Path` 是文件系统路径，不是
模块路径。

而扫描器原代码在整条匹配链路上，凡是遇到 `Replace != nil` 就无条件改用
`Replace` 的字段，于是在三个环节先后把这条漏洞静默丢弃：

1. **漏洞库查询阶段**（`internal/vulncheck/fetch.go`）
   用 `Replace.Path`（本地目录 `../localmods/x-text`）作为模块路径去漏洞库
   查询。库里没有这个"模块"，`moduleMetas` 匹配为空，直接返回 0 条 OSV，
   该模块在进入版本判断之前就被整体丢掉。

2. **版本区间匹配阶段**（`internal/vulncheck/affectingVulnerabilities`）
   取版本时 `modVersion = module.Replace.Version`，本地替换下它是空串。
   `affected()` 对空版本和 `(devel)` 一律返回 `false`（设计上为避免对未知
   版本误报），于是即使查到了 OSV，也会在区间匹配处被全部过滤。

3. **包/符号匹配阶段**（`ForPackage`）
   它用 `Replace.Path` 去改写导入路径（把 `golang.org/x/text/language`
   改写成 `../localmods/x-text/language`）。OSV 条目的包路径是真实导入路径
   `golang.org/x/text/language`，改写后永远匹配不上，包级和符号级结论被
   全部丢弃。

三处叠加，最终零告警、退出码 0。这也解释了"显式写了版本也不算数"：版本写在
了外层，而扫描器只认 `Replace` 内层，内层对本地目录天然没有版本。

## 三、修复方案与取舍

核心思路：**区分"本地目录替换"和"模块到模块替换"**。只有前者需要回落到
go.mod 声明的模块身份与版本；后者（含带版本的 replace）维持原行为不变。

新增判定 `isLocalReplace`（`internal/vulncheck/utils.go`）：go 命令对本地
目录替换的表示是 `Replace.Version` 为空，且路径为绝对路径或以 `.`/`..`
开头的相对路径。带版本的 replace 一定是另一个模块，不落入此分支。

据此在三个丢弃点分别修复：

- `modPath`：本地目录替换时返回原模块路径（`mod.Path`），不用文件系统路径。
- `modVersion`：仅当 `Replace.Version` 非空时采用它，否则回落到外层
  `mod.Version`（即 go.mod 声明、go 命令保留在外层的版本）。
- `fetch.go`：本地目录替换用原模块路径查询漏洞库，恢复 OSV 拉取。
- `affectingVulnerabilities`：统一改用 `modVersion()`，显式版本本地替换
  得以通过区间匹配。
- `ForPackage`：本地目录替换不改写导入路径，保留真实导入路径，使包级与
  符号级匹配继续生效。
- `emit.go` 的输出帧：统一走 `modPath/modVersion`，避免把本地文件系统路径
  和空版本写进 finding。

### 边界与不变量（对应修复要求）

- **符号级精度不变**：本地目录替换不改写导入路径后，`ForSymbol` 仍按调用图
  实际可达性判定。新增用例专门验证：可达的 `Parse` 报出，未在 OSV 中声明的
  `Other` 符号不误报。
- **未声明版本的 replace 维持现状**：外层 `Version` 也为空时，`modVersion`
  仍返回空，`affected()` 依旧保守返回 false，不产生告警，不纳入本题。
  由 `TestUnversionedLocalReplaceUnchanged` 锁定。
- **模块到模块替换行为不变**：带版本的 replace 仍以替换模块的路径/版本为准，
  既有的 `TestVulnsForPackageReplaced`、`TestFetchVulnerabilities` 全绿。
- **其余输出与退出码不变**：没有改动任何输出模板、handler 或退出码逻辑。
  finding 恢复后，退出码由既有的"发现漏洞→3"机制自然产生；无漏洞仍为 0。
- **二进制模式同步受益**：source 与 binary 共用上述匹配函数，两条链路行为
  一致；SBOM 清单仍按原样呈现替换实体，未在本次改动范围内。

## 四、回归测试

1. 单元测试 `internal/vulncheck/local_replace_test.go`（6 个）：
   - `isLocalReplace` 的本地/模块/绝对/相对/带版本判定；
   - `modPath/modVersion` 在本地替换、模块替换、无版本三种情形的取值；
   - 显式版本本地替换能通过 `affectingVulnerabilities` 区间匹配（核心回归）；
   - `ForPackage/ForSymbol` 按真实导入路径与可达符号判定，含负例；
   - `FetchVulnerabilities` 用原模块路径查到 OSV；
   - 未声明版本本地替换维持 0 匹配的现状。
2. 端到端夹具（完全离线，不依赖模块代理）：
   - `cmd/govulncheck/testdata/common/modules/localreplace/`：主模块以
     显式版本本地 replace 引用一个本地 stub 模块，stub 保留 GO-2021-0113
     声明的 `golang.org/x/text/language.Parse` 符号与导入路径。
   - `.../source-call/source_localreplace_text.ct`：断言扫描报出
     GO-2021-0113，模块/版本显示为 `golang.org/x/text@v0.3.0`，调用链
     `localreplace.main calls language.Parse`，退出码 3。

## 五、验证

- `go build ./...`、`go vet ./internal/vulncheck/...`、`gofmt` 均通过。
- `go test ./internal/vulncheck/...` 通过；新增 6 个单测全部 PASS。
- 离线（`GOPROXY=off GOSUMDB=off`）下 `go test ./cmd/govulncheck/ -run
  TestCommand/common` 全绿，含既有 replace 用例与新增本地 replace 用例。
- 复现工程端到端：修复前 `No vulnerabilities found`/exit 0；修复后报出
  GO-2021-0113、exit 3，JSON 帧模块/版本/包路径正确且不泄漏本地路径。

注：本机默认网络无法访问 `proxy.golang.org`/sumdb，直接跑全量 `go test ./...`
时，`internal/buildinfo` 与 `cmd/govulncheck` 中需要联网 `go build` 拉模块的
用例会在 10 分钟测试超时处 panic（与本次改动无关，这些包/用例未被修改）。
设置 `GOPROXY=off GOSUMDB=off` 后这些用例改用本地缓存即可正常通过。
