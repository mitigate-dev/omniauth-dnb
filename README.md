# OmniAuth DNB

Omniauth strategy for using [Luminor Link](https://www.luminor.lv/en/terms-conditions#luminor-link) as an authentication service provider.

Supported Ruby versions: 2.7+

## Related projects

- [omniauth-citadele](https://github.com/mitigate-dev/omniauth-citadele) - strategy for authenticating with Citadele
- [omniauth-nordea](https://github.com/mitigate-dev/omniauth-nordea) - strategy for authenticating with Nordea
- [omniauth-seb-elink](https://github.com/mitigate-dev/omniauth-seb-elink) - strategy for authenticating with SEB
- [omniauth-swedbank](https://github.com/mitigate-dev/omniauth-swedbank) - strategy for authenticating with Swedbank

## Installation

Add this line to your application's Gemfile (omniauth-rails_csrf_protection is required if using Rails):

    gem 'omniauth-rails_csrf_protection'
    gem 'omniauth-dnb'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install omniauth-rails_csrf_protection omniauth-dnb

## Usage

Here's a quick example, adding the middleware to a Rails app
in `config/initializers/omniauth.rb`:

```ruby
Rails.application.config.middleware.use OmniAuth::Builder do
  provider :dnb,
    File.read("path/to/private.key"),
    File.read("path/to/bank.crt"),
    ENV['DNB_SND_ID'],
    site: ENV['DNB_SITE'] || OmniAuth::Strategies::Dnb::PRODUCTION_ENDPOINT
end
```

## Auth Hash

Here's an example Auth Hash available in `request.env['omniauth.auth']`:

```ruby
{
  provider: 'dnb',
  uid: '374042-80367',
  info: {
    full_name: 'ARNIS RAITUMS'
  },
  extra: {
    raw_info: {
      VK_SERVICE: '2001',
      VK_VERSION: '101',
      VK_SND_ID: 'RIKOLV2X',
      VK_REC_ID: '10..',
      VK_STAMP: '20170403112855087471',
      VK_T_NO: '616365957',
      VK_PER_CODE: '374042-80367',
      VK_PER_FNAME: 'ARNIS',
      VK_PER_LNAME: 'RAITUMS',
      VK_COM_CODE: '',
      VK_COM_NAME: '',
      VK_TIME: '20170403113328',
      VK_MAC: 'SkYmH5AFI6Av ...',
      VK_LANG: 'LAT'
    }
  }
}
```

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request
