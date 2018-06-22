-- ----------------------------
-- Table structure for wx_sys_user
-- ----------------------------
DROP TABLE IF EXISTS `wx_sys_user`;
CREATE TABLE `wx_sys_user` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT COMMENT '主键ID',
  `user_id` bigint(20) DEFAULT NULL COMMENT '设备用户ID',
  `password` varchar(100) COLLATE utf8_bin DEFAULT NULL COMMENT '绑定用户密码，用于用户自动登录',
  `open_id` varchar(100) COLLATE utf8_bin DEFAULT NULL COMMENT '微信用户OpenID',
  `create_time` datetime DEFAULT NULL COMMENT '绑定时间',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin COMMENT='微信公众号账号与设备用户关联表';


-- ----------------------------
-- Table structure for wx_access_token
-- ----------------------------
DROP TABLE IF EXISTS `wx_access_token`;
CREATE TABLE `wx_access_token` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT COMMENT '主键ID',
  `access_token` varchar(255) COLLATE utf8_bin DEFAULT NULL COMMENT '微信接入Token',
  `expires_in` int(255) DEFAULT NULL COMMENT 'Token有效时间(单位：秒)',
  `create_time` datetime DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP COMMENT '获取凭证时间',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin COMMENT='微信接入Token表';