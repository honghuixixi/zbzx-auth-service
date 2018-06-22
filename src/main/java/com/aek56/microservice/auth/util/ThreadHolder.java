package com.aek56.microservice.auth.util;

public class ThreadHolder {

	private static final ThreadLocal<String> holder = new ThreadLocal<String>();

	public static String get() {
		return holder.get();
	}

	public static void set(String value) {
		holder.set(value);
	}

	public static void remove() {
		holder.remove();
	}
}
