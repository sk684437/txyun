// 专用 WebSocket 路由：/ws
// 与官方 WebSocket 模板（TencentEdgeOne/pages-websocket）结构保持一致，
// 用一个独立的入口文件承载 WS 升级请求。
export { onRequest, onRequest as default } from './_websocket.js';
