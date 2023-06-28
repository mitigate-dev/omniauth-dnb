require 'spec_helper'

describe OmniAuth::Strategies::Dnb do

  PRIVATE_KEY = File.read(File.join(RSpec.configuration.cert_folder, 'bank.key'))
  PUBLIC_KEY = File.read(File.join(RSpec.configuration.cert_folder, 'bank.crt'))

  let(:app){ Rack::Builder.new do |b|
    b.use Rack::Session::Cookie, { secret: 'abc123'}
    b.use(OmniAuth::Strategies::Dnb, PRIVATE_KEY, PUBLIC_KEY, 'MY_SND_ID')
    b.run lambda{|env| [404, {}, ['Not Found']]}
  end.to_app }
  let(:last_response_stamp) { last_response.body.match(/name="VK_STAMP" value="([^"]*)"/)[1] }
  let(:last_response_mac)   { last_response.body.match(/name="VK_MAC" value="([^"]*)"/)[1] }

  context 'request phase' do
    before(:each){ get '/auth/dnb' }

    it 'displays a single form' do
      expect(last_response.status).to eq(200)
      expect(last_response.body.scan('<form').size).to eq(1)
    end

    it 'has JavaScript code to submit the form after it is created' do
      expect(last_response.body).to be_include('</form><script type="text/javascript">document.forms[0].submit();</script>')
    end

    EXPECTED_VALUES = {
      VK_SERVICE: '3001',
      VK_VERSION: '101',
      VK_SND_ID:  'MY_SND_ID',
      VK_RETURN:  'http://example.org/auth/dnb/callback'
    }

    EXPECTED_VALUES.each_pair do |k,v|
      it 'has hidden input field #{k} => #{v}' do
        expect(last_response.body.scan("<input type=\"hidden\" name=\"#{k}\" value=\"#{v}\"").size).to eq(1)
      end
    end

    it 'has a VK_STAMP hidden field with 20 byte long value' do
      expect(last_response_stamp.bytesize).to eq(20)
    end

    it 'has a correct VK_MAC signature' do
      sig_str =
        "004#{EXPECTED_VALUES[:VK_SERVICE]}" +
        "003#{EXPECTED_VALUES[:VK_VERSION]}" +
        "009#{EXPECTED_VALUES[:VK_SND_ID]}" +
        "020" + last_response_stamp +  # VK_STAMP
        "036#{EXPECTED_VALUES[:VK_RETURN]}"

      private_key = OpenSSL::PKey::RSA.new(PRIVATE_KEY)
      expected_mac = Base64.encode64(private_key.sign(OpenSSL::Digest::SHA1.new, sig_str))
      expect(last_response_mac).to eq(expected_mac)
    end

    context 'with default options' do
      it 'has the default action tag value' do
        expect(last_response.body).to be_include("action='#{OmniAuth::Strategies::Dnb::PRODUCTION_ENDPOINT}'")
      end

      it 'has the default VK_LANG value' do
        expect(last_response.body.scan('<input type="hidden" name="VK_LANG" value="ENG"').size).to eq(1)
      end
    end

    context 'with custom options' do
      let(:app){ Rack::Builder.new do |b|
        b.use Rack::Session::Cookie, { secret: 'abc123' }
        b.use(OmniAuth::Strategies::Dnb, PRIVATE_KEY, PUBLIC_KEY, 'MY_SND_ID',
          site: 'https://test.lv/banklink')
        b.run lambda{|env| [404, {}, ['Not Found']]}
      end.to_app }

      it 'has the custom action tag value' do
        expect(last_response.body).to be_include("action='https://test.lv/banklink'")
      end
    end

    context 'with non-existant private key files' do
      let(:app){ Rack::Builder.new do |b|
        b.use Rack::Session::Cookie, { secret: 'abc123' }
        b.use(OmniAuth::Strategies::Dnb, 'invalid_key', PUBLIC_KEY, 'MY_SND_ID')
        b.run lambda{|env| [404, {}, ['Not Found']]}
      end.to_app }

      it 'redirects to /auth/failure with appropriate query params' do
        expect(last_response.status).to eq(302)
        expect(last_response.headers['Location']).to eq('/auth/failure?message=private_key_load_err&strategy=dnb')
      end
    end
  end

  context 'callback phase' do
    let(:auth_hash){ last_request.env['omniauth.auth'] }
    context 'with valid response' do
      before do
        post '/auth/dnb/callback',
          'VK_SERVICE': '2001',
          'VK_VERSION': '101',
          'VK_SND_ID': 'RIKOLV2X',
          'VK_REC_ID': 'MY_SND_ID',
          'VK_STAMP': '20170403112855087471',
          'VK_T_NO': '616365957',
          'VK_PER_CODE': '121200-00005',
          'VK_PER_FNAME': 'USER_5',
          'VK_PER_LNAME': 'TEST',
          'VK_COM_CODE': '',
          'VK_COM_NAME': '',
          'VK_TIME': '20170403113328',
          'VK_MAC': 'dNj8PfJhwK8wm2UXRegkknqzIDmiHb+13UOJ2j1cI5dnC31kcosDQGJQrh9AJdUGtD9CHX8FIXtwPI0B+HAdiO3rdJxmc1vi68czGX79YQnbgl9pAc7WVLV6Lpv01bdAkVowGBvac6JlcFangx1e6dRqDQjCK5Q1p9PFqDcxBRtOkKMOlfBSFRQ4GNTC+t2AvXycQtFWScB3Z9GSA04xZrPA7yeEY1RtrkCxCbIGpr9vPN4wAdhCMeHqW8BHH5ir/ripo5krOynnmwHEJkj5sSq0cLsffbEP+15i3VuVp+S95/qmr9WQpS/F9tgGWDnZ0y+tsYs4BH5hQZxI+zH05Q==',
          'VK_LANG': 'LAT'
      end

      it 'sets the correct uid value in the auth hash' do
        expect(auth_hash.uid).to eq('121200-00005')
      end

      it 'sets the correct info.full_name value in the auth hash' do
        expect(auth_hash.info.full_name).to eq('USER_5 TEST')
      end
    end

    context 'with non-existant public key file' do
      let(:app){ Rack::Builder.new do |b|
        b.use Rack::Session::Cookie, { secret: 'abc123' }
        b.use(OmniAuth::Strategies::Dnb, PRIVATE_KEY, 'invalid_crt', 'MY_SND_ID')
        b.run lambda{|env| [404, {}, ['Not Found']]}
      end.to_app }

      it 'redirects to /auth/failure with appropriate query params' do
        post '/auth/dnb/callback' # Params are not important, because we're testing public key loading
        expect(last_response.status).to eq(302)
        expect(last_response.headers['Location']).to eq('/auth/failure?message=public_key_load_err&strategy=dnb')
      end
    end

    context 'with invalid response' do
      it 'detects invalid signature' do
        post '/auth/dnb/callback',
          'VK_SERVICE': '2001',
          'VK_VERSION': '101',
          'VK_SND_ID': 'RIKOLV2X',
          'VK_REC_ID': 'MY_SND_ID',
          'VK_STAMP': '20170403112855087471',
          'VK_T_NO': '616365957',
          'VK_PER_CODE': '121200-00005',
          'VK_PER_FNAME': 'USER_5',
          'VK_PER_LNAME': 'TEST',
          'VK_COM_CODE': '',
          'VK_COM_NAME': '',
          'VK_TIME': '20170403113328',
          'VK_MAC': 'invalid_signature',
          'VK_LANG': 'LAT'

        expect(last_response.status).to eq(302)
        expect(last_response.headers['Location']).to eq('/auth/failure?message=invalid_response_signature_err&strategy=dnb')
        expect(auth_hash).to be_nil
      end

      it 'detects unsupported VK_SERVICE values' do
        post '/auth/dnb/callback',
          'VK_SERVICE': '2004',
          'VK_VERSION': '101',
          'VK_SND_ID': 'RIKOLV2X',
          'VK_REC_ID': 'MY_SND_ID',
          'VK_STAMP': '20170403112855087471',
          'VK_T_NO': '616365957',
          'VK_PER_CODE': '121200-00005',
          'VK_PER_FNAME': 'USER_5',
          'VK_PER_LNAME': 'TEST',
          'VK_COM_CODE': '',
          'VK_COM_NAME': '',
          'VK_TIME': '20170403113328',
          'VK_MAC': 'dNj8PfJhwK8wm2UXRegkknqzIDmiHb+13UOJ2j1cI5dnC31kcosDQGJQrh9AJdUGtD9CHX8FIXtwPI0B+HAdiO3rdJxmc1vi68czGX79YQnbgl9pAc7WVLV6Lpv01bdAkVowGBvac6JlcFangx1e6dRqDQjCK5Q1p9PFqDcxBRtOkKMOlfBSFRQ4GNTC+t2AvXycQtFWScB3Z9GSA04xZrPA7yeEY1RtrkCxCbIGpr9vPN4wAdhCMeHqW8BHH5ir/ripo5krOynnmwHEJkj5sSq0cLsffbEP+15i3VuVp+S95/qmr9WQpS/F9tgGWDnZ0y+tsYs4BH5hQZxI+zH05Q==',
          'VK_LANG': 'LAT'

        expect(last_response.status).to eq(302)
        expect(last_response.headers['Location']).to eq('/auth/failure?message=unsupported_response_service_err&strategy=dnb')
        expect(auth_hash).to be_nil
      end

      it 'detects unsupported VK_VERSION values' do
        post '/auth/dnb/callback',
          'VK_SERVICE': '2001',
          'VK_VERSION': '109',
          'VK_SND_ID': 'RIKOLV2X',
          'VK_REC_ID': 'MY_SND_ID',
          'VK_STAMP': '20170403112855087471',
          'VK_T_NO': '616365957',
          'VK_PER_CODE': '121200-00005',
          'VK_PER_FNAME': 'USER_5',
          'VK_PER_LNAME': 'TEST',
          'VK_COM_CODE': '',
          'VK_COM_NAME': '',
          'VK_TIME': '20170403113328',
          'VK_MAC': 'dNj8PfJhwK8wm2UXRegkknqzIDmiHb+13UOJ2j1cI5dnC31kcosDQGJQrh9AJdUGtD9CHX8FIXtwPI0B+HAdiO3rdJxmc1vi68czGX79YQnbgl9pAc7WVLV6Lpv01bdAkVowGBvac6JlcFangx1e6dRqDQjCK5Q1p9PFqDcxBRtOkKMOlfBSFRQ4GNTC+t2AvXycQtFWScB3Z9GSA04xZrPA7yeEY1RtrkCxCbIGpr9vPN4wAdhCMeHqW8BHH5ir/ripo5krOynnmwHEJkj5sSq0cLsffbEP+15i3VuVp+S95/qmr9WQpS/F9tgGWDnZ0y+tsYs4BH5hQZxI+zH05Q==',
          'VK_LANG': 'LAT'

        expect(last_response.status).to eq(302)
        expect(last_response.headers['Location']).to eq('/auth/failure?message=unsupported_response_version_err&strategy=dnb')
        expect(auth_hash).to be_nil
      end
    end
  end
end
