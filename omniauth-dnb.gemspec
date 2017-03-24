# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'omniauth/dnb/version'

Gem::Specification.new do |spec|
  spec.name          = "omniauth-dnb"
  spec.version       = Omniauth::Dnb::VERSION
  spec.authors       = ["MAK IT"]
  spec.email         = ["info@makit.lv"]
  spec.description   = %q{OmniAuth strategy for DNB Link}
  spec.summary       = %q{OmniAuth strategy for DNB Link}
  spec.homepage      = ""
  spec.license       = "MIT"

  spec.files         = `git ls-files`.split($/)
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_runtime_dependency 'omniauth', '~> 1.0'
  spec.add_runtime_dependency "i18n"

  spec.add_development_dependency 'rack-test'
  spec.add_development_dependency 'rspec', '~> 2.7'
  spec.add_development_dependency "bundler", "~> 1.3"
  spec.add_development_dependency "rake"
end
