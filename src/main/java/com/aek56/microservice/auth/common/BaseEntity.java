package com.aek56.microservice.auth.common;


import java.io.Serializable;

import org.apache.commons.lang3.builder.ReflectionToStringBuilder;

/**
 * Entity 基类
 *
 * @author zj@aek56.com
 */
public abstract class BaseEntity implements Serializable {

	private static final long serialVersionUID = 1L;
	/**
     * 实体编号（唯一标识）
     */
    private Long id;

    public BaseEntity() {

    }

    public BaseEntity(Long id) {
        this();
        this.id = id;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    @Override
    public String toString() {
        return ReflectionToStringBuilder.toString(this);
    }

}
