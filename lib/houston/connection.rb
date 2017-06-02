require 'uri'
require 'socket'
require 'openssl'
require 'forwardable'

module Houston
  class Connection
    # クラスに対し、メソッドの委譲機能を定義するモジュール
    # 継承やMix-inでは機能を持つクラスを取り込む必要がある
    # 以上では一部の機能だけ取り込むことができる
    # 委譲元と委譲先で親子関係が生まれない
    extend Forwardable
    # sslというオブジェクトにreadとwriteメソッドを委譲する
    # def_delegatorならエイリアスも貼れる
    def_delegators :@ssl, :read, :write
    def_delegators :@uri, :scheme, :host, :port

    attr_reader :ssl, :socket, :certificate, :passphrase

    class << self
      def open(uri, certificate, passphrase)
        return unless block_given?

        connection = new(uri, certificate, passphrase)
        connection.open

        yield connection

        connection.close
      end
    end

    def initialize(uri, certificate, passphrase)
      @uri = URI(uri)
      @certificate = certificate.to_s
      @passphrase = passphrase.to_s
    end

    # SSLコネクションを確立する
    def open
      return false if open?

      # TCPソケットを確率する
      @socket = TCPSocket.new(@uri.host, @uri.port)

      # コンテキストを設定
      context = OpenSSL::SSL::SSLContext.new
      # 証明書とパスから鍵を取得する
      context.key = OpenSSL::PKey::RSA.new(@certificate, @passphrase)
      # 証明書
      context.cert = OpenSSL::X509::Certificate.new(@certificate)

      # TCPソケットをラップしてSSLでの認証と暗号通信を確立する
      @ssl = OpenSSL::SSL::SSLSocket.new(@socket, context)
      # ラップしているTCPソケットを同期させる
      @ssl.sync = true
      @ssl.connect
    end

    # 確立しているか？
    def open?
      not (@ssl && @socket).nil?
    end

    def close
      return false if closed?

      @ssl.close
      @ssl = nil

      @socket.close
      @socket = nil
    end

    def closed?
      not open?
    end
  end
end
