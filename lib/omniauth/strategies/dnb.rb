require 'omniauth'
require 'base64'

module OmniAuth
  module Strategies
    class Dnb
      include OmniAuth::Strategy

      AUTH_SERVICE = '3001'
      AUTH_VERSION = '101'  # This value must not be used as a number, so as to not lose the padding
                            # Padding is important when generating the VK_MAC value

      args [:private_key_file, :public_key_file, :snd_id]

      option :private_key_file, nil
      option :public_key_file, nil
      option :snd_id, nil

      option :name, 'dnb'
      option :site, 'https://ib.dnb.lv/login/index.php'

      def callback_url
        full_host + script_name + callback_path
      end

      def stamp
        return @stamp if @stamp
        @stamp = ((full_host.gsub(/[\:\/]/, "X") + SecureRandom.uuid.gsub("-", "")).rjust 50, " ")[-50, 50]
      end

      def prepend_length(value)
        # prepend length to string in 0xx format

        [ value.to_s.length.to_s.rjust(3, '0'), value.dup.to_s.force_encoding("ascii")].join
      end

      def signature_input
        [
          AUTH_SERVICE,                 # VK_SERVICE
          AUTH_VERSION,                 # VK_VERSION
          options.snd_id,               # VK_SND_ID
          stamp,                        # VK_STAMP
          callback_url                  # VK_RETURN
        ].map{|v| prepend_length(v)}.join
      end

      def signature(priv_key)
        Base64.encode64(priv_key.sign(OpenSSL::Digest::SHA1.new, signature_input))
      end

      uid do
        request.params["VK_INFO"].match(/ISIK:(\d{6}\-\d{5})/)[1]
      end

      info do
        {
          :full_name => request.params["VK_INFO"].match(/NIMI:(.+)/)[1]
        }
      end

      def callback_phase
        begin
          pub_key = OpenSSL::X509::Certificate.new(File.read(options.public_key_file || "")).public_key
        rescue => e
          return fail!(:public_key_load_err, e)
        end

        if request.params['VK_SERVICE'] != '3001'
          return fail!(:unsupported_response_service_err)
        end

        if request.params['VK_VERSION'] != '101'
          return fail!(:unsupported_response_version_err)
        end

        if request.params['VK_ENCODING'] != 'UTF-8'
          return fail!(:unsupported_response_encoding_err)
        end

        sig_str = [
          request.params["VK_SERVICE"],
          request.params["VK_VERSION"],
          request.params["VK_SND_ID"],
          request.params["VK_STAMP"],
          request.params["VK_NONCE"],
          request.params["VK_INFO"]
        ].map(&:prepend_length).join

        raw_signature = Base64.decode64(request.params["VK_MAC"])

        if !pub_key.verify(OpenSSL::Digest::SHA1.new, raw_signature, sig_str)
          return fail!(:invalid_response_signature_err)
        end

        super
      rescue => e
        fail!(:unknown_callback_err, e)
      end

      def request_phase
        begin
          priv_key = OpenSSL::PKey::RSA.new(File.read(options.private_key_file || ""))
        rescue => e
          return fail!(:private_key_load_err, e)
        end

        OmniAuth.config.form_css = nil
        form = OmniAuth::Form.new(:title => I18n.t("omniauth.dnb.please_wait"), :url => options.site)

        {
          "VK_SERVICE" => AUTH_SERVICE,
          "VK_VERSION" => AUTH_VERSION,
          "VK_SND_ID" => options.snd_id,
          "VK_STAMP" => stamp,
          "VK_RETURN" => callback_url,
          "VK_MAC" => signature(priv_key),
          "VK_LANG" => "LAT",
        }.each do |name, val|
          form.html "<input type=\"hidden\" name=\"#{name}\" value=\"#{val}\" />"
        end

        form.button I18n.t("omniauth.dnb.click_here_if_not_redirected")

        form.instance_variable_set("@html",
          form.to_html.gsub("</form>", "</form><script type=\"text/javascript\">document.forms[0].submit();</script>"))
        form.to_response
      rescue => e
        fail!(:unknown_request_err, e)
      end
    end
  end
end
