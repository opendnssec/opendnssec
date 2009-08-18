module KASPAuditor
  class AuditorDaemon
    attr_accessor :kasp_file, :conf_file, :zone_name, :signed_temp

    def run
      daemonize
      run_loop
    end


    def daemonize
      if (not fork)
        # get our own session and fixup std[in,out,err]
        Process.setsid
        STDIN.close()
        oldstdout = STDOUT
        STDOUT.reopen'/dev/null'
        STDERR.reopen'/dev/null'
        if (not fork)
          oldstdout.write("running as pid #{Process.pid}\n")
          # hang around till adopted by init
          ppid = Process.ppid
          while (ppid != 1)
            sleep(0.5)
            ppid = Process.ppid
          end
        else
          # time for child to die
          exit(0)
        end
      else
        Process.wait
        Process.exit
      end
    end

    def run_loop
      while (true)
        fork {
          runner = Runner.new
          runner.conf_file = @conf_file
          if (@kasp_file)
            runner.kasp_file = @kasp_file
          end
          if (@zone_name)
            runner.zone_name = @zone_name
            if (@signed_temp)
              runner.signed_temp = @signed_temp
            end
          end
          runner.run
        }
        sleep(3600)
      end
    end
  end
end