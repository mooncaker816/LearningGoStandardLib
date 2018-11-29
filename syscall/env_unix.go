// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build darwin dragonfly freebsd js,wasm linux nacl netbsd openbsd solaris

// Unix environment variables.

package syscall

import "sync"

var (
	// envOnce guards initialization by copyenv, which populates env.
	envOnce sync.Once

	// envLock guards env and envs.
	envLock sync.RWMutex

	// env maps from an environment variable to its first occurrence in envs.
	// [Min] key 为环境变量的 key，int 值代表该环境变量的字符形式“key=value”在 envs 中的索引
	// [Min] 对于重复的 key 只保留 envs 中的第一个
	env map[string]int

	// envs is provided by the runtime. elements are expected to
	// be of the form "key=value". An empty string means deleted
	// (or a duplicate to be ignored).
	// [Min] 环境变量
	envs []string = runtime_envs()
)

// runtime 包中定义，返回系统环境变量的深拷贝
func runtime_envs() []string // in package runtime

// setenv_c and unsetenv_c are provided by the runtime but are no-ops
// if cgo isn't loaded.
func setenv_c(k, v string)
func unsetenv_c(k string)

// [Min] 拷贝，去重 envs，得到新的映射 env
func copyenv() {
	env = make(map[string]int)
	for i, s := range envs {
		// [Min] 根据 key=value 的格式解析出 key
		for j := 0; j < len(s); j++ {
			if s[j] == '=' {
				key := s[:j]
				// [Min] key 如果有重复，只保留第一个
				if _, ok := env[key]; !ok {
					env[key] = i // first mention of key
				} else {
					// Clear duplicate keys. This permits Unsetenv to
					// safely delete only the first item without
					// worrying about unshadowing a later one,
					// which might be a security problem.
					envs[i] = ""
				}
				break
			}
		}
	}
}

// 删除环境变量 key
func Unsetenv(key string) error {
	// [Min] 确保环境变量已经拷贝到 env，且只拷贝一次
	envOnce.Do(copyenv)

	envLock.Lock()
	defer envLock.Unlock()

	// [Min] 更新本地的 envs,env
	if i, ok := env[key]; ok {
		// [Min] 整个 key=value 字符串置为空
		envs[i] = ""
		// [Min] 注意是删除，不只是将值置为空
		delete(env, key)
	}
	// [Min] 调用 cgo 程序，如果有的话
	unsetenv_c(key)
	return nil
}

// [Min] 获取环境变量 key
func Getenv(key string) (value string, found bool) {
	envOnce.Do(copyenv)
	if len(key) == 0 {
		return "", false
	}

	envLock.RLock()
	defer envLock.RUnlock()

	// [Min] 从拷贝中查找 key，如果没有直接返回空和 false
	i, ok := env[key]
	if !ok {
		return "", false
	}
	// [Min] env 中找到了 key，通过索引 i 在 envs 中获取 key=value，
	// [Min] 再将 value 部分的值返回，同时返回 true
	s := envs[i]
	for i := 0; i < len(s); i++ {
		if s[i] == '=' {
			return s[i+1:], true
		}
	}
	// [Min] 如果没有"="，非法，不应该出现
	return "", false
}

// [Min] 设置环境变量 key=value
func Setenv(key, value string) error {
	envOnce.Do(copyenv)
	// [Min] key 不能为空
	if len(key) == 0 {
		return EINVAL
	}
	// [Min] key 不能包含'=',0(不是字符0)
	for i := 0; i < len(key); i++ {
		if key[i] == '=' || key[i] == 0 {
			return EINVAL
		}
	}
	// [Min] value 不能包含0(不是字符0)
	for i := 0; i < len(value); i++ {
		if value[i] == 0 {
			return EINVAL
		}
	}

	envLock.Lock()
	defer envLock.Unlock()

	// [Min] 更新 env，envs
	i, ok := env[key]
	kv := key + "=" + value
	if ok {
		envs[i] = kv
	} else {
		i = len(envs)
		envs = append(envs, kv)
	}
	env[key] = i
	// [Min] cgo 设置环境变量，如果有的话
	setenv_c(key, value)
	return nil
}

// [Min] 清空环境变量
func Clearenv() {
	envOnce.Do(copyenv) // prevent copyenv in Getenv/Setenv

	envLock.Lock()
	defer envLock.Unlock()

	for k := range env {
		unsetenv_c(k)
	}
	env = make(map[string]int)
	envs = []string{}
}

// [Min] 返回当前所有的环境变量字符串切片
func Environ() []string {
	envOnce.Do(copyenv)
	envLock.RLock()
	defer envLock.RUnlock()
	a := make([]string, 0, len(envs))
	// [Min] 去掉 envs 中无效的空串，其余的都返回
	for _, env := range envs {
		if env != "" {
			a = append(a, env)
		}
	}
	return a
}
