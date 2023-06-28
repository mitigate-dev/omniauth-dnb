require 'omniauth'
require 'base64'

module OmniAuth
  module Strategies
    class Dnb
      include OmniAuth::Strategy

      PRODUCTION_ENDPOINT = 'https://ib.dnb.lv/login/index.php'
      TEST_ENDPOINT = 'https://link.securet.dnb.lv/login/rid_login.php'

      AUTH_SERVICE = '3001'
      AUTH_VERSION = '101'

      def self.render_nonce?
         defined?(ActionDispatch::ContentSecurityPolicy::Request) != nil
      end
      if render_nonce?
        include ActionDispatch::ContentSecurityPolicy::Request
        delegate :get_header, :set_header, to: :request
      end

      args [:private_key, :public_key, :snd_id]

      option :private_key, nil
      option :public_key, nil
      option :snd_id, nil

      option :name, 'dnb'
      option :site, PRODUCTION_ENDPOINT

      def stamp
        return @stamp if @stamp
        @stamp = Time.now.strftime('%Y%m%d%H%M%S') + SecureRandom.random_number(999999).to_s.rjust(6, '0')
      end

      def prepend_length(value)
        # prepend length to string in 0xx format
        [ value.to_s.length.to_s.rjust(3, '0'), value.dup.to_s.force_encoding('ascii')].join
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
        if request.params['VK_PER_CODE']
          request.params['VK_PER_CODE']
        else
          request.params['VK_COM_CODE']
        end
      end

      info do
        full_name = if request.params['VK_PER_FNAME']
          [request.params['VK_PER_FNAME'], request.params['VK_PER_LNAME']].join(' ')
        else
          request.params['VK_COM_NAME']
        end
        {
          full_name: full_name,
          first_name: request.params['VK_PER_FNAME'],
          last_name: request.params['VK_PER_LNAME'],
          company_code: request.params['VK_COM_CODE'],
          company_name: request.params['VK_COM_NAME'],
        }
      end

      extra do
        { raw_info: request.params }
      end

      def callback_phase
        begin
          pub_key = OpenSSL::X509::Certificate.new(options.public_key).public_key
        rescue => e
          return fail!(:public_key_load_err, e)
        end

        if request.params['VK_SERVICE'] != '2001'
          return fail!(:unsupported_response_service_err)
        end

        if request.params['VK_VERSION'] != '101'
          return fail!(:unsupported_response_version_err)
        end

        sig_str = [
          request.params['VK_SERVICE'],
          request.params['VK_VERSION'],
          request.params['VK_SND_ID'],
          request.params['VK_REC_ID'],
          request.params['VK_STAMP'],
          request.params['VK_T_NO'],
          request.params['VK_PER_CODE'],
          request.params['VK_PER_FNAME'],
          request.params['VK_PER_LNAME'],
          request.params['VK_COM_CODE'],
          request.params['VK_COM_NAME'],
          request.params['VK_TIME']
        ].map{|v| prepend_length(v)}.join

        raw_signature = Base64.decode64(request.params['VK_MAC'])

        if !pub_key.verify(OpenSSL::Digest::SHA1.new, raw_signature, sig_str)
          return fail!(:invalid_response_signature_err)
        end

        super
      end

      def request_phase
        begin
          priv_key = OpenSSL::PKey::RSA.new(options.private_key)
        rescue => e
          return fail!(:private_key_load_err, e)
        end

        set_locale_from_query_param

        form = OmniAuth::Form.new(:title => I18n.t('omniauth.dnb.please_wait'), :url => options.site)

        {
          'VK_SERVICE' => AUTH_SERVICE,
          'VK_VERSION' => AUTH_VERSION,
          'VK_SND_ID' => options.snd_id,
          'VK_STAMP' => stamp,
          'VK_RETURN' => callback_url,
          'VK_MAC' => signature(priv_key),
          'VK_LANG' => resolve_bank_ui_language,
        }.each do |name, val|
          form.html "<input type=\"hidden\" name=\"#{name}\" value=\"#{val}\" />"
        end

        form.button I18n.t('omniauth.dnb.click_here_if_not_redirected')

        nonce_attribute = nil
        if self.class.render_nonce?
          nonce_attribute = " nonce='#{escape(content_security_policy_nonce)}'"
        end

        form.instance_variable_set('@html',
          form.to_html.gsub('</form>', "</form><script type=\"text/javascript\"#{nonce_attribute}>document.forms[0].submit();</script>"))
        form.to_response
      end

      private

      def set_locale_from_query_param
        locale = request.params['locale']
        if (locale != nil && locale.strip != '' && I18n.locale_available?(locale))
          I18n.locale = locale
        end
      end

      def resolve_bank_ui_language
        case I18n.locale
        when :ru then 'RUS'
        when :en then 'ENG'
        else 'LAT'
        end
      end

      def escape(html_attribute_value)
         CGI.escapeHTML(html_attribute_value) unless html_attribute_value.nil?
      end
    end
  end
end
