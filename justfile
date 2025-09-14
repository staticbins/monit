set unstable
set script-interpreter := ["just", "interpreter"]
set dotenv-load
set dotenv-filename := x"${GITHUB_ENV:-.env.build}"

container := if env_var_or_default('USE_PODMAN', 'true') == 'true' { "podman" } else { "docker" }
container_name := "alpine_monit_build"

export NAME := "monit"
export REPO := env_var_or_default("REPO", "staticbins/monit")
export VERSION := env_var_or_default("VERSION", "1.0.0")
export CHECKOUT_URL := env_var_or_default("CHECKOUT_URL", "https://github.com/" + REPO + ".git")
export CHECKOUT_DEPTH := env_var_or_default("CHECKOUT_DEPTH", "1")
export CHECKOUT_REF := env_var_or_default("CHECKOUT_REF", "master")
export TARGET_OS := env_var_or_default("TARGET_OS", os())
export TARGET_ARCH := env_var_or_default("TARGET_ARCH", arch())
export ENV_FILE := env_var_or_default("GITHUB_ENV", justfile_directory() / ".env.build")
export WORK_DIR := justfile_directory()
export BUILD_DIR := WORK_DIR / "build"
export DIST_DIR := WORK_DIR/ "dist"
export DIST_NAME := NAME + "-" + VERSION + "-" + TARGET_OS + "-" + TARGET_ARCH

version:
  @cat {{BUILD_DIR}}/CHANGES | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n 1

env:
  #!/usr/bin/env sh
  cd {{justfile_directory()}}
  rm -f {{ENV_FILE}}

  export VERSION="$(just version)"
  export RELEASE_NAME="$VERSION"
  export RELEASED=$(gh release view $RELEASE_NAME > /dev/null 2>&1 && echo true || echo false)

  echo "NAME={{NAME}}" >> {{ENV_FILE}}
  echo "REPO={{REPO}}" >> {{ENV_FILE}}
  echo "VERSION=$VERSION" >> {{ENV_FILE}}
  echo "CHECKOUT_URL={{CHECKOUT_URL}}" >> {{ENV_FILE}}
  echo "CHECKOUT_DEPTH={{CHECKOUT_DEPTH}}" >> {{ENV_FILE}}
  echo "CHECKOUT_REF=$VERSION" >> {{ENV_FILE}}
  echo "TARGET_OS={{TARGET_OS}}" >> {{ENV_FILE}}
  echo "TARGET_ARCH={{TARGET_ARCH}}" >> {{ENV_FILE}}
  echo "RELEASE_NAME=$RELEASE_NAME" >> {{ENV_FILE}}
  echo "RELEASED=$RELEASED" >> {{ENV_FILE}}
  cat {{ENV_FILE}}

setup:
  mkdir -p {{BUILD_DIR}}
  {{container}} run --name {{container_name}} -td -v {{BUILD_DIR}}:/build -w /build alpine /bin/sh

[script]
install:
  sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories
  apk update
  apk add build-base autoconf automake libtool m4 bison flex zlib-dev zlib-static openssl-dev openssl-libs-static  ncurses

checkout:
  git clone --depth {{CHECKOUT_DEPTH}} -b {{CHECKOUT_REF}} {{CHECKOUT_URL}} {{BUILD_DIR}}

[script]
compile:
  ./bootstrap
  ./configure CFLAGS="-static" --enable-static --without-pam
  make LDFLAGS="-all-static" -j$(nproc)

package:
  rm -rf {{DIST_DIR}}
  mkdir -p {{DIST_DIR}}/bin
  mkdir -p {{DIST_DIR}}/etc
  cd {{BUILD_DIR}} && cp monit {{DIST_DIR}}/bin/monit
  cd {{BUILD_DIR}} && cp monitrc {{DIST_DIR}}/etc/monitrc
  cd {{DIST_DIR}} && tar -zcvf {{WORK_DIR}}/{{DIST_NAME}}.tar.gz .
  mv {{WORK_DIR}}/{{DIST_NAME}}.tar.gz {{DIST_DIR}}

pipe:
  just setup
  just install
  just checkout
  just env
  just compile
  just package
  just teardown

clean:
  rm -rf {{ENV_FILE}}
  rm -rf {{BUILD_DIR}}
  rm -rf {{DIST_DIR}}

teardown:
  {{container}} stop {{container_name}}
  {{container}} rm {{container_name}}


[script]
hi:
  uname
  ls /

interpreter s:
  @cat "{{s}}" | sed '1d' | sed '/./,$!d' | podman exec -i alpine_monit_build /bin/sh
