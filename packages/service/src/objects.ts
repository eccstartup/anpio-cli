// 附件对象的字节放哪：**文件系统，按摘要寻址**（attachments.md §4）。
//
// 三条理由，都不是"图省事"：
//
//   - **去重是免费的。** 同一份字节上传两次落在同一个路径上。§3.8 L180 那条"一个附件对象
//     只上传一次"说的是多设备不要各造一份，把它推到存储层就是这个形状。
//   - **不用 sqlite BLOB。** 库是**顺序与幂等的台账**，WAL 每次检查点都要搬动脏页；几 MiB
//     的对象体混在里面，等于让每条消息的提交都背着一份附件。
//   - **文件自己的名字就是它的完整性主张。** §7.4 L472 要求 `digest` 是上传字节的 SHA-256，
//     于是"路径 = 摘要"这件事本身就是校验，不需要另写一套。
//
// 落盘顺序是两段：`PUT` 边收边算摘要、写进 `<dir>/tmp/<slot_id>`；`commit_object` 校验
// `size` 与摘要之后才搬进 `<dir>/objects/<digest>`。**没提交的对象不可被引用**
// （§10.1 L826 那句"拿到 `object_uri` 不等于对象可用"），所以 `object_uri` 从 `create_slot`
// 就发出去、但它指向的东西到 `commit` 才存在——`object_uri` 是 locator，不是"东西已经在
// 那了"的断言（§7.5 L489）。

import { createHash } from 'node:crypto'
import { createReadStream, createWriteStream, existsSync, mkdirSync, renameSync, rmSync, statSync } from 'node:fs'
import { join } from 'node:path'
import type { Readable } from 'node:stream'
import { once } from 'node:events'

const TMP = 'tmp'
const OBJECTS = 'objects'

/**
 * P1 §core binding **L482**：需要传输二进制负载时，字段 **MUST** 采用**无填充 base64url**
 * 文本表示。Node 的 `'base64url'` 编解码器就是这一种（字母表 `-`/`_`，不带 `=`），所以这里
 * 不另写一份——`digest.value_b64u`、`download_ticket_b64u` 与磁盘文件名是同一个表示。
 *
 * 32 字节的 SHA-256 编码出来恒为 43 字符。这个长度既是"值对不对"的形状检查，也是下面
 * 路径拼接的**安全边界**：摘要从 URL 里来，不校验形状就等于把 `../` 交给 `join()`。
 */
const DIGEST_PATTERN = /^[A-Za-z0-9_-]{43}$/

export function isObjectDigest(value: string): boolean {
  return DIGEST_PATTERN.test(value)
}

/** `slot_id` 的形状。与摘要不同，这不是协议固定的东西——`create_slot` 自己造它——所以规则
 *  由本服务定：一段 URL 安全的随机串，够长到撞不上，且不含路径分隔符。它是拼进路径的一段，
 *  所以这既是卫生检查也是那一段的边界。 */
const SLOT_ID_PATTERN = /^[A-Za-z0-9_-]{16,64}$/

/** 上传超过 `AGENTX_MAX_OBJECT_BYTES`。数据面把它翻成 `413` + 6003（§12 L1091）。 */
export class ObjectTooLargeError extends Error {
  constructor(readonly limit: number) {
    super(`object exceeds the ${limit} byte limit`)
    this.name = 'ObjectTooLargeError'
  }
}

/** 一个已经收完但还没提交的上传。 */
export interface StagedObject {
  /** 收到的字节数。`commit_object` 拿它和请求里的 `size` 对，不符即 6010（§10.3.2 L925）。 */
  size: number
  /** 收到字节的 SHA-256，无填充 base64url。 */
  digest: string
}

export interface ObjectStore {
  /** 边收边算摘要，写进暂存区。超限抛 {@link ObjectTooLargeError}，并抹掉半截的暂存文件。 */
  accept(slotId: string, body: AsyncIterable<Uint8Array>): Promise<StagedObject>
  /** 把暂存文件搬成最终对象。`digest` 已由调用方校验过形状。 */
  commit(slotId: string, digest: string): void
  /** 丢掉暂存文件（`abort_object`，或收流失败后的清理）。不存在也算成功。 */
  discard(slotId: string): void
  /** 打开一个已提交对象供下载流式读出；没这个对象就返回 `undefined`。 */
  open(digest: string): Readable | undefined
  /** 已提交对象的大小，用来在下载响应里给 `content-length`。 */
  sizeOf(digest: string): number | undefined
}

class FilesystemObjectStore implements ObjectStore {
  constructor(
    private readonly root: string,
    private readonly maxBytes: number,
  ) {
    // 失败就让它失败在启动那一刻：一个写不进去的对象目录，比一个跑起来之后每次上传才
    // 报错的目录好查得多。
    mkdirSync(join(root, TMP), { recursive: true })
    mkdirSync(join(root, OBJECTS), { recursive: true })
  }

  /** `slot_id` 由本服务铸出（`create_slot` 的响应里发出去那个），但仍过一遍形状检查：
   *  它是拼进路径的一段，而"这个值只可能是我们自己造的"是一句需要证明的话，不是一个
   *  可以依赖的前提。 */
  private tmpPath(slotId: string): string {
    if (!SLOT_ID_PATTERN.test(slotId)) throw new Error(`refusing to stage an upload under ${JSON.stringify(slotId)}`)
    return join(this.root, TMP, slotId)
  }

  private objectPath(digest: string): string {
    if (!isObjectDigest(digest)) throw new Error(`refusing to address an object by ${JSON.stringify(digest)}`)
    return join(this.root, OBJECTS, digest)
  }

  async accept(slotId: string, body: AsyncIterable<Uint8Array>): Promise<StagedObject> {
    const path = this.tmpPath(slotId)
    const hash = createHash('sha256')
    const sink = createWriteStream(path)
    let writeError: Error | undefined
    // Node 在没有 'error' 监听者时会把流的错误抛成**未捕获异常**（进程退出）。所以这里先接
    // 住：超过上限的那条路会 `destroy()` 再删文件，而那个还没飞回来的 `open` 回调正好在那
    // 之后失败——于是"拒绝一个大文件"会变成"整个进程退出"。错误记下来，由下面的 try/catch
    // 和末尾那一次检查决定它是什么。
    sink.on('error', (err: Error) => {
      writeError = err
    })
    let size = 0
    try {
      for await (const chunk of body) {
        size += chunk.byteLength
        // 约束在**收流的过程中**，不是收完之后——先缓冲再判断等于把上限变成了内存用量
        // （attachments.md §4）。
        if (size > this.maxBytes) throw new ObjectTooLargeError(this.maxBytes)
        hash.update(chunk)
        // `write()` 返回 false 是背压信号：不理会它，几 MiB 的流会整个堆在内存里。
        // `once` 在等 'drain' 期间若来一个 'error' 会直接拒绝，所以卡死的写盘不会永远挂着。
        if (!sink.write(chunk)) await once(sink, 'drain')
      }
      await new Promise<void>((resolve, reject) => {
        sink.end((err?: Error | null) => (err == null ? resolve() : reject(err)))
      })
    } catch (err) {
      sink.destroy()
      rmSync(path, { force: true })
      throw err
    }
    if (writeError !== undefined) {
      rmSync(path, { force: true })
      throw writeError
    }
    return { size, digest: hash.digest('base64url') }
  }

  commit(slotId: string, digest: string): void {
    // `rename` 在同一文件系统内是原子的，所以不存在"搬了一半"的对象：下载路由要么看不见
    // 它，要么看见的就是完整的它。已经存在同一个摘要时直接覆盖——同样的摘要就是同样的
    // 字节（§7.4 L472），覆盖等于把一份等价的文件写到自己的位置上。
    //
    // 但**已经搬过一次**、或者暂存文件已被清掉时要直接返回：`commit_object` 的事务有可能
    // 回滚（比如 `insertAttachmentObject` 撞了行），此时对象已经躺在最终位置了，客户端重试
    // 会再走一遍这里。`rename` 撞上一个不存在的源文件是抛错，于是"一次回滚过的提交"变成
    // 永远修不好的一行——同一个摘要就是同一份字节，没有暂存文件也只说明它已经就位。
    const target = this.objectPath(digest)
    try {
      renameSync(this.tmpPath(slotId), target)
    } catch (err) {
      if (existsSync(target)) return
      throw err
    }
  }

  discard(slotId: string): void {
    rmSync(this.tmpPath(slotId), { force: true })
  }

  open(digest: string): Readable | undefined {
    if (!isObjectDigest(digest)) return undefined
    const path = this.objectPath(digest)
    try {
      statSync(path)
    } catch {
      return undefined
    }
    return createReadStream(path)
  }

  sizeOf(digest: string): number | undefined {
    if (!isObjectDigest(digest)) return undefined
    try {
      return statSync(this.objectPath(digest)).size
    } catch {
      return undefined
    }
  }
}

export interface OpenObjectStoreOptions {
  /** 对象目录：`AGENTX_OBJECT_DIR`，不给则由 config 推一个（attachments.md §4）。 */
  directory: string
  /** 单个对象的上限，`AGENTX_MAX_OBJECT_BYTES`。 */
  maxBytes: number
}

export function openObjectStore(options: OpenObjectStoreOptions): ObjectStore {
  return new FilesystemObjectStore(options.directory, options.maxBytes)
}
